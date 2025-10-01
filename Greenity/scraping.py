import requests
from bs4 import BeautifulSoup
import json
import re
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
import time

class RecyclingPointsScraper:
    """Scraper para puntos de reciclaje de la Alcaldía de Barranquilla"""
    
    def __init__(self, url: str = "https://www.barranquilla.gov.co/gestion-ambiental/donde-entrego-el-material-reciclable"):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def extract_location_info(self, text: str) -> Dict[str, str]:
        """Extrae información de dirección y teléfono de cada punto"""
        # Patrón para detectar direcciones y teléfonos
        phone_pattern = r'\((\d+(?:-\d+)?)\)'
        
        phones = re.findall(phone_pattern, text)
        # Remover teléfonos del texto para obtener la dirección limpia
        address = re.sub(phone_pattern, '', text).strip()
        
        return {
            'nombre': address,
            'telefono': ', '.join(phones) if phones else 'No disponible'
        }
    
    def parse_category(self, card_element) -> Dict[str, any]:
        """Parsea una categoría de reciclaje completa"""
        try:
            # Extraer título de la categoría
            title_element = card_element.find('h3')
            if not title_element:
                return None
            
            title = title_element.get_text(strip=True)
            
            # Extraer ID del collapse para obtener el contenido
            collapse_link = card_element.find('a', {'data-bs-toggle': 'collapse'})
            if not collapse_link:
                return None
            
            collapse_id = collapse_link.get('href', '').replace('#', '')
            
            # Encontrar el div con el contenido
            content_div = card_element.find('div', {'id': collapse_id})
            if not content_div:
                return None
            
            # Extraer todos los puntos de reciclaje (elementos <li>)
            location_items = content_div.find_all('li')
            locations = []
            
            for item in location_items:
                text = item.get_text(strip=True)
                if text:
                    location_info = self.extract_location_info(text)
                    location_info['texto_completo'] = text
                    locations.append(location_info)
            
            # Separar material y organización del título
            parts = title.split('-')
            material = parts[0].strip() if len(parts) > 0 else title
            organizacion = parts[1].strip() if len(parts) > 1 else 'No especificada'
            
            return {
                'material': material,
                'organizacion': organizacion,
                'titulo_completo': title,
                'total_puntos': len(locations),
                'puntos': locations
            }
            
        except Exception as e:
            print(f"Error parseando categoría: {e}")
            return None
    
    def scrape(self) -> Dict[str, any]:
        """Ejecuta el scraping completo"""
        start_time = time.time()
        
        try:
            print(f"🔍 Iniciando scraping de: {self.url}")
            response = self.session.get(self.url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Buscar el acordeón principal
            accordion = soup.find('div', {'id': 'accordion'})
            if not accordion:
                return {
                    'success': False,
                    'error': 'No se encontró el acordeón en la página',
                    'data': []
                }
            
            # Encontrar todas las tarjetas (categorías)
            cards = accordion.find_all('div', class_='card')
            
            print(f"📦 Encontradas {len(cards)} categorías de reciclaje")
            
            # Parsear todas las categorías
            categories = []
            for card in cards:
                category_data = self.parse_category(card)
                if category_data:
                    categories.append(category_data)
                    print(f"   ✓ {category_data['titulo_completo']}: {category_data['total_puntos']} puntos")
            
            elapsed_time = time.time() - start_time
            
            # Calcular estadísticas
            total_points = sum(cat['total_puntos'] for cat in categories)
            
            result = {
                'success': True,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'tiempo_ejecucion': f"{elapsed_time:.2f} segundos",
                'estadisticas': {
                    'total_categorias': len(categories),
                    'total_puntos': total_points
                },
                'categorias': categories
            }
            
            print(f"\n✅ Scraping completado en {elapsed_time:.2f}s")
            print(f"📊 Total: {len(categories)} categorías, {total_points} puntos de reciclaje")
            
            return result
            
        except requests.RequestException as e:
            return {
                'success': False,
                'error': f'Error de conexión: {str(e)}',
                'data': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error inesperado: {str(e)}',
                'data': []
            }
    
    def save_to_json(self, data: Dict, filename: str = 'puntos_reciclaje_barranquilla.json'):
        """Guarda los datos en formato JSON"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"\n💾 Datos guardados en: {filename}")
            return True
        except Exception as e:
            print(f"❌ Error guardando archivo: {e}")
            return False
    
    def print_summary(self, data: Dict):
        """Imprime un resumen legible de los datos"""
        if not data.get('success'):
            print(f"\n❌ Error: {data.get('error')}")
            return
        
        print("\n" + "="*60)
        print("📍 PUNTOS DE RECICLAJE - BARRANQUILLA")
        print("="*60)
        
        for categoria in data['categorias']:
            print(f"\n🔹 {categoria['titulo_completo']}")
            print(f"   Organización: {categoria['organizacion']}")
            print(f"   Total de puntos: {categoria['total_puntos']}")
            print(f"   Puntos:")
            for i, punto in enumerate(categoria['puntos'][:3], 1):  # Mostrar solo 3 primeros
                print(f"      {i}. {punto['nombre']}")
                if punto['telefono'] != 'No disponible':
                    print(f"         Tel: {punto['telefono']}")
            if len(categoria['puntos']) > 3:
                print(f"      ... y {len(categoria['puntos']) - 3} puntos más")


def main():
    """Función principal para ejecutar el scraper"""
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║   SCRAPER DE PUNTOS DE RECICLAJE - BARRANQUILLA         ║
    ║   Alcaldía de Barranquilla                               ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Crear instancia del scraper
    scraper = RecyclingPointsScraper()
    
    # Ejecutar scraping
    data = scraper.scrape()
    
    # Mostrar resumen
    scraper.print_summary(data)
    
    # Guardar en JSON
    if data.get('success'):
        scraper.save_to_json(data)
        
        # Mostrar cómo acceder a los datos
        print("\n" + "="*60)
        print("💡 CÓMO USAR LOS DATOS:")
        print("="*60)
        print("1. Los datos están en: puntos_reciclaje_barranquilla.json")
        print("2. Estructura: categorias -> puntos -> {nombre, telefono}")
        print("3. Ejemplo de acceso:")
        print("   data['categorias'][0]['puntos'][0]['nombre']")
    
    return data


if __name__ == "__main__":
    # Ejecutar el scraper
    result = main()
    
    # Ejemplo de búsqueda específica
    if result.get('success'):
        print("\n" + "="*60)
        print("🔍 EJEMPLO: Buscar puntos para reciclar PILAS")
        print("="*60)
        
        for categoria in result['categorias']:
            if 'Pilas' in categoria['material']:
                print(f"\n✓ {categoria['titulo_completo']}")
                print(f"  Organización: {categoria['organizacion']}")
                print(f"  Puntos disponibles: {categoria['total_puntos']}")
                for punto in categoria['puntos'][:5]:
                    print(f"    • {punto['texto_completo']}")