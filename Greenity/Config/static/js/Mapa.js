// JavaScript optimizado para la página del mapa

document.addEventListener("DOMContentLoaded", function () {
  // Elementos del DOM
  const distanceSlider = document.getElementById("distance-slider");
  const distanceValue = document.getElementById("distance-value");
  const materialCheckboxes = document.querySelectorAll(".material-checkbox");
  const scheduleCheckboxes = document.querySelectorAll(".schedule-checkbox");
  const applyFiltersBtn = document.querySelector(".apply-filters-btn");
  const listViewBtn = document.getElementById("list-view");
  const gridViewBtn = document.getElementById("grid-view");
  const pointsContainer = document.getElementById("points-container");
  const myLocationBtn = document.getElementById("my-location-btn");
  const fullscreenBtn = document.getElementById("fullscreen-btn");
  const actionBtns = document.querySelectorAll(".action-btn");
  const updateDataBtn = document.getElementById("update-data-btn");
  const dataStatus = document.getElementById("data-status");
  const statusText = document.getElementById("status-text");

  // Variables globales
  let currentView = "list";
  let currentFilters = {
    distance: 1,
    materials: [],
    schedules: [],
  };
  let puntosReciclaje = []; // Datos del scraping
  let leafletMap = null;
  let markersGroup = null;

  // Inicialización
  init();

  async function init() {
    setupDistanceSlider();
    setupCheckboxes();
    setupViewControls();
    setupMapControls();
    setupActionButtons();
    setupUpdateDataButton();
    
    // Cargar datos del scraping
    await loadRecyclingPoints();
    
    // Inicializar mapa después de cargar datos
    setTimeout(initLeafletMap, 100);
    console.log("Mapa de reciclaje cargado correctamente");
  }

  // Cargar puntos de reciclaje desde la API
  async function loadRecyclingPoints() {
    try {
      console.log("Cargando datos de puntos de reciclaje...");
      const response = await fetch('/api/puntos-reciclaje');
      const data = await response.json();
      
      if (data.success && data.categorias) {
        puntosReciclaje = processScrapingData(data.categorias);
        updatePointCards();
        updateMaterialFilters(data.categorias);
        console.log(`Cargados ${puntosReciclaje.length} puntos de reciclaje`);
      } else {
        console.error("Error cargando datos:", data.error);
        // Usar datos de ejemplo si no se pueden cargar los reales
        puntosReciclaje = getExamplePoints();
      }
    } catch (error) {
      console.error("Error en la petición:", error);
      // Usar datos de ejemplo si hay error en la conexión
      puntosReciclaje = getExamplePoints();
    }
  }

  // Procesar datos del scraping para el formato del mapa
  function processScrapingData(categorias) {
    const puntos = [];
    let id = 1;

    categorias.forEach(categoria => {
      categoria.puntos.forEach(punto => {
        const coordinates = extractCoordinatesFromAddress(punto.nombre);
        
        puntos.push({
          id: id++,
          name: punto.nombre,
          address: punto.texto_completo,
          phone: punto.telefono,
          lat: coordinates.lat,
          lng: coordinates.lng,
          materials: [categoria.material],
          category: categoria.material,
          organization: categoria.organizacion,
          type: getPointType(categoria.organizacion),
          distance: Math.random() * 5 + 0.5, // Distancia simulada
          status: "open", // Estado simulado
          rating: (Math.random() * 2 + 3).toFixed(1), // Rating simulado
          schedule: "Lun-Vie: 8:00-18:00" // Horario simulado
        });
      });
    });

    return puntos;
  }

  // Extraer coordenadas aproximadas basadas en la dirección
  function extractCoordinatesFromAddress(address) {
    // Coordenadas base de Barranquilla
    const baseCoords = { lat: 10.9639, lng: -74.7964 };
    
    // Generar coordenadas aleatorias dentro de Barranquilla
    // En un desarrollo real, esto se haría con un servicio de geocodificación
    const offset = 0.05; // Aproximadamente 5km de radio
    const randomLat = baseCoords.lat + (Math.random() - 0.5) * offset;
    const randomLng = baseCoords.lng + (Math.random() - 0.5) * offset;
    
    return {
      lat: parseFloat(randomLat.toFixed(6)),
      lng: parseFloat(randomLng.toFixed(6))
    };
  }

  // Determinar tipo de punto basado en la organización
  function getPointType(organizacion) {
    if (organizacion.toLowerCase().includes('fundación') || 
        organizacion.toLowerCase().includes('ong')) {
      return 'empresas';
    } else if (organizacion.toLowerCase().includes('centro') || 
               organizacion.toLowerCase().includes('mall')) {
      return 'centros';
    } else if (organizacion.toLowerCase().includes('universidad') || 
               organizacion.toLowerCase().includes('colegio')) {
      return 'universidades';
    }
    return 'empresas'; // Por defecto
  }

  // Datos de ejemplo como fallback
  function getExamplePoints() {
    return [
      {
        id: 1,
        name: "EcoPunto El Prado",
        address: "Cra. 54 #70-174, El Prado",
        phone: "300-123-4567",
        lat: 10.9685,
        lng: -74.7813,
        materials: ["Plástico", "Papel", "Vidrio", "Metal"],
        category: "Múltiples materiales",
        organization: "Alcaldía de Barranquilla",
        type: "empresas",
        distance: 0.8,
        status: "open",
        rating: "4.5",
        schedule: "Lun-Vie: 8:00-18:00, Sáb: 9:00-14:00"
      },
      {
        id: 2,
        name: "Centro de Acopio Norte",
        address: "Calle 84 #43-50, Riomar",
        phone: "300-987-6543",
        lat: 10.9780,
        lng: -74.7890,
        materials: ["Papel", "Cartón", "Pilas", "Electrónicos"],
        category: "Papel y electrónicos",
        organization: "EcoNorte",
        type: "centros",
        distance: 1.2,
        status: "open",
        rating: "4.2",
        schedule: "Lun-Dom: 24 horas"
      }
    ];
  }

  // Actualizar filtros de materiales dinámicamente
  function updateMaterialFilters(categorias) {
    const materialesUnicos = [...new Set(categorias.map(cat => cat.material))];
    const checkboxContainer = document.querySelector('.checkbox-group');
    
    if (checkboxContainer) {
      // Limpiar checkboxes existentes
      checkboxContainer.innerHTML = '';
      
      // Crear checkboxes dinámicos
      materialesUnicos.forEach((material, index) => {
        const materialKey = material.toLowerCase().replace(/\s+/g, '');
        const checkboxHTML = `
          <label class="checkbox-item">
            <input type="checkbox" class="material-checkbox" value="${materialKey}">
            <span class="checkmark"></span>
            <span class="checkbox-text">${material}</span>
          </label>
        `;
        checkboxContainer.insertAdjacentHTML('beforeend', checkboxHTML);
      });
      
      // Volver a configurar event listeners
      setupCheckboxes();
    }
  }

  // Generar HTML para las tarjetas de puntos
  function updatePointCards() {
    if (!pointsContainer) return;
    
    const cardsHTML = puntosReciclaje.map(punto => `
      <div class="point-card" data-type="${punto.type}" data-id="${punto.id}">
        <div class="point-header">
          <div class="point-icon">
            <i class="fas fa-recycle"></i>
          </div>
          <div class="point-info">
            <h3 class="point-name">${punto.name}</h3>
            <p class="point-address">${punto.address}</p>
            <div class="point-status">
              <span class="distance">${punto.distance.toFixed(1)} km</span>
              <span class="status ${punto.status}">• ${punto.status === 'open' ? 'Abierto' : 'Cerrado'}</span>
            </div>
          </div>
          <div class="point-rating">
            <i class="fas fa-star"></i>
            <span>${punto.rating}</span>
          </div>
        </div>
        <div class="point-materials">
          ${punto.materials.map(material => `<span class="material-tag">${material}</span>`).join('')}
        </div>
        <div class="point-schedule">
          <i class="fas fa-clock"></i>
          <span>${punto.schedule}</span>
        </div>
        <div class="point-phone" style="margin: 10px 0;">
          <i class="fas fa-phone"></i>
          <span>${punto.phone}</span>
        </div>
        <div class="point-organization" style="margin: 10px 0; color: #666;">
          <i class="fas fa-building"></i>
          <span>${punto.organization}</span>
        </div>
        <div class="point-actions">
          <button class="action-btn primary" onclick="openDirections(${punto.lat}, ${punto.lng})">
            <i class="fas fa-paper-plane"></i>
            Cómo llegar
          </button>
          <button class="action-btn" onclick="callPhone('${punto.phone}')">
            <i class="fas fa-phone"></i>
            Llamar
          </button>
          <button class="action-btn" onclick="showPointDetails(${punto.id})">
            <i class="fas fa-info-circle"></i>
            Ver detalles
          </button>
        </div>
      </div>
    `).join('');
    
    pointsContainer.innerHTML = cardsHTML;
    
    // Volver a configurar event listeners para las nuevas tarjetas
    setupPointCards();
  }
  // Configurar slider de distancia
  function setupDistanceSlider() {
    if (distanceSlider && distanceValue) {
      distanceSlider.addEventListener("input", function () {
        const value = this.value;
        distanceValue.textContent = `${value} km`;
        currentFilters.distance = parseInt(value);
        this.style.background = `linear-gradient(to right, #22c55e 0%, #22c55e ${
          (value / 20) * 100
        }%, #e5e7eb ${(value / 20) * 100}%, #e5e7eb 100%)`;
      });
      distanceSlider.dispatchEvent(new Event("input"));
    }
  }

  // Configurar checkboxes
  function setupCheckboxes() {
    // Limpiar listeners previos y obtener elementos actuales
    const currentMaterialCheckboxes = document.querySelectorAll(".material-checkbox");
    const currentScheduleCheckboxes = document.querySelectorAll(".schedule-checkbox");
    
    currentMaterialCheckboxes.forEach((checkbox) => {
      checkbox.addEventListener("change", function () {
        if (this.checked) {
          currentFilters.materials.push(this.value);
        } else {
          currentFilters.materials = currentFilters.materials.filter(
            (m) => m !== this.value
          );
        }
        updateFilterCount();
      });
    });

    currentScheduleCheckboxes.forEach((checkbox) => {
      checkbox.addEventListener("change", function () {
        if (this.checked) {
          currentFilters.schedules.push(this.value);
        } else {
          currentFilters.schedules = currentFilters.schedules.filter(
            (s) => s !== this.value
          );
        }
        updateFilterCount();
      });
    });
  }

  // Actualizar contador de filtros
  function updateFilterCount() {
    const totalFilters = currentFilters.materials.length + currentFilters.schedules.length;
    if (totalFilters > 0) {
      applyFiltersBtn.innerHTML = `<i class="fas fa-filter"></i> Aplicar Filtros (${totalFilters})`;
    } else {
      applyFiltersBtn.innerHTML = `<i class="fas fa-filter"></i> Aplicar Filtros`;
    }
  }

  // Configurar controles de vista
  function setupViewControls() {
    if (listViewBtn && gridViewBtn && pointsContainer) {
      listViewBtn.addEventListener("click", () => switchView("list"));
      gridViewBtn.addEventListener("click", () => switchView("grid"));
    }
  }

  // Cambiar vista
  function switchView(view) {
    if (currentView === view) return;
    currentView = view;
    listViewBtn.classList.toggle("active", view === "list");
    gridViewBtn.classList.toggle("active", view === "grid");
    pointsContainer.classList.toggle("grid-view", view === "grid");
  }

  // Configurar controles del mapa
  function setupMapControls() {
    if (myLocationBtn) {
      myLocationBtn.addEventListener("click", getCurrentLocation);
    }
    if (fullscreenBtn) {
      fullscreenBtn.addEventListener("click", toggleFullscreen);
    }
  }

  // Obtener ubicación actual
  function getCurrentLocation() {
    if (navigator.geolocation) {
      myLocationBtn.innerHTML = 'Obteniendo ubicación...';
      myLocationBtn.disabled = true;

      navigator.geolocation.getCurrentPosition(
        function (position) {
          const lat = position.coords.latitude;
          const lng = position.coords.longitude;

          if (window.leafletMap) {
            window.leafletMap.setView([lat, lng], 15);
            L.marker([lat, lng])
              .addTo(window.leafletMap)
              .bindPopup("📍 Tu ubicación actual")
              .openPopup();
          }

          myLocationBtn.innerHTML = '<i class="fas fa-crosshairs"></i> Mi Ubicación';
          myLocationBtn.disabled = false;
        },
        function (error) {
          myLocationBtn.innerHTML = '<i class="fas fa-crosshairs"></i> Mi Ubicación';
          myLocationBtn.disabled = false;
          alert("No se pudo obtener tu ubicación. Verifica los permisos de geolocalización.");
        }
      );
    } else {
      alert("Tu navegador no soporta geolocalización.");
    }
  }

  // Alternar pantalla completa
  function toggleFullscreen() {
    const mapContainer = document.querySelector(".map-container");
    if (!document.fullscreenElement) {
      mapContainer.requestFullscreen().then(() => {
        fullscreenBtn.innerHTML = '<i class="fas fa-compress"></i>';
      }).catch(err => console.log("Error pantalla completa:", err));
    } else {
      document.exitFullscreen().then(() => {
        fullscreenBtn.innerHTML = '<i class="fas fa-expand"></i>';
      }).catch(err => console.log("Error salir pantalla completa:", err));
    }
  }

  // Configurar tarjetas de puntos
  function setupPointCards() {
    pointCards.forEach((card) => {
      card.addEventListener("mouseenter", function () {
        this.style.transform = "translateY(-5px)";
      });
      card.addEventListener("mouseleave", function () {
        this.style.transform = "translateY(0)";
      });
    });
  }

  // Configurar botones de acción
  function setupActionButtons() {
    actionBtns.forEach((btn) => {
      btn.addEventListener("click", function (e) {
        e.stopPropagation();
        
        const action = this.textContent.trim();
        const card = this.closest(".point-card");
        const pointName = card.querySelector(".point-name").textContent;

        if (action.includes("Cómo llegar")) {
          alert(`Abriendo Google Maps para: ${pointName}`);
        } else if (action.includes("Llamar")) {
          const phoneNumber = "+54 11 1234-5678";
          if (confirm(`¿Llamar a ${pointName}?\nTeléfono: ${phoneNumber}`)) {
            window.location.href = `tel:${phoneNumber}`;
          }
        } else if (action.includes("Ver detalles")) {
          alert(`Detalles de ${pointName} - Funcionalidad próximamente disponible.`);
        }
      });
    });
  }

  // Aplicar filtros
  function applyFilters() {
    const pointCards = document.querySelectorAll(".point-card");
    
    pointCards.forEach((card) => {
      let show = true;
      const cardId = parseInt(card.dataset.id);
      const punto = puntosReciclaje.find(p => p.id === cardId);
      
      if (!punto) return;

      // Filtrar por distancia
      if (punto.distance > currentFilters.distance) {
        show = false;
      }

      // Filtrar por materiales
      if (currentFilters.materials.length > 0) {
        const hasMaterial = currentFilters.materials.some(filter =>
          punto.materials.some(material => 
            material.toLowerCase().includes(filter) || 
            filter.includes(material.toLowerCase().replace(/\s+/g, ''))
          )
        );
        if (!hasMaterial) show = false;
      }

      // Filtrar por horarios
      if (currentFilters.schedules.length > 0) {
        const schedule = punto.schedule.toLowerCase();
        const hasSchedule = currentFilters.schedules.some((filter) => {
          switch (filter) {
            case "24h":
              return schedule.includes("24 horas");
            case "comercial":
              return schedule.includes("8:00") || schedule.includes("9:00");
            case "fines":
              return schedule.includes("sáb") || schedule.includes("dom");
            case "semana":
              return schedule.includes("lun-vie") || schedule.includes("lun-fri");
            default:
              return false;
          }
        });
        if (!hasSchedule) show = false;
      }

      // Mostrar/ocultar tarjeta
      card.style.display = show ? "block" : "none";
    });
    
    // Actualizar marcadores en el mapa
    updateMapMarkers();
  }

  // Event listener para aplicar filtros
  if (applyFiltersBtn) {
    applyFiltersBtn.addEventListener("click", applyFilters);
  }
  
  // Configurar botón de actualización de datos
  function setupUpdateDataButton() {
    if (updateDataBtn) {
      updateDataBtn.addEventListener("click", async function() {
        await updateRecyclingData();
      });
    }
  }
  
  // Actualizar datos ejecutando scraping
  async function updateRecyclingData() {
    try {
      showDataStatus("Actualizando datos...", "loading");
      updateDataBtn.disabled = true;
      updateDataBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Actualizando...';
      
      const response = await fetch('/api/ejecutar-scraping', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      });
      
      const result = await response.json();
      
      if (result.success) {
        showDataStatus(`Datos actualizados exitosamente. ${result.estadisticas.total_puntos} puntos encontrados.`, "success");
        
        // Recargar datos actualizados
        await loadRecyclingPoints();
        updateMapMarkers();
        
      } else {
        showDataStatus(`Error: ${result.error}`, "error");
      }
      
    } catch (error) {
      console.error("Error actualizando datos:", error);
      showDataStatus("Error de conexión al actualizar datos", "error");
    } finally {
      updateDataBtn.disabled = false;
      updateDataBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Actualizar Datos';
    }
  }
  
  // Mostrar estado de los datos
  function showDataStatus(message, type) {
    if (dataStatus && statusText) {
      statusText.textContent = message;
      dataStatus.style.display = "block";
      
      // Remover clases previas
      dataStatus.classList.remove("status-loading", "status-success", "status-error");
      
      // Agregar clase según el tipo
      dataStatus.classList.add(`status-${type}`);
      
      // Ocultar después de 5 segundos (excepto para loading)
      if (type !== "loading") {
        setTimeout(() => {
          dataStatus.style.display = "none";
        }, 5000);
      }
    }
  }
});

// Función para inicializar el mapa de Leaflet
function initLeafletMap() {
  const mapContainer = document.getElementById("map");
  if (!mapContainer) {
    console.error("No se encontró el contenedor del mapa");
    return;
  }

  // Inicializar el mapa centrado en Barranquilla
  leafletMap = L.map("map").setView([10.9639, -74.7964], 13);
  window.leafletMap = leafletMap;

  // Forzar redimensionamiento del mapa
  setTimeout(() => leafletMap.invalidateSize(), 250);

  // Añadir tiles de OpenStreetMap
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19,
    attribution: "© OpenStreetMap contributors",
  }).addTo(leafletMap);

  // Crear grupo de marcadores
  markersGroup = L.layerGroup().addTo(leafletMap);

  // Agregar todos los marcadores
  updateMapMarkers();

  console.log('Mapa de Leaflet inicializado correctamente');
}

// Actualizar marcadores en el mapa según filtros
function updateMapMarkers() {
  if (!markersGroup || !leafletMap) return;
  
  // Limpiar marcadores existentes
  markersGroup.clearLayers();
  
  // Obtener puntos visibles (según filtros)
  const visibleCards = document.querySelectorAll(".point-card:not([style*='display: none'])");
  const visibleIds = Array.from(visibleCards).map(card => parseInt(card.dataset.id));
  
  // Agregar marcadores para puntos visibles
  puntosReciclaje.forEach(function(punto) {
    if (!visibleIds.includes(punto.id)) return;
    
    // Crear icono personalizado según el tipo
    const iconClass = getIconClass(punto.type);
    const customIcon = L.divIcon({
      html: `<div class="custom-marker ${punto.type}"><i class="${iconClass}"></i></div>`,
      className: 'custom-marker-container',
      iconSize: [30, 30],
      iconAnchor: [15, 15]
    });
    
    const marker = L.marker([punto.lat, punto.lng], { icon: customIcon });
    
    const popupContent = `
      <div style="min-width: 250px; max-width: 300px;">
        <h3 style="color: #22c55e; margin: 0 0 10px 0; font-size: 16px;">${punto.name}</h3>
        <p style="margin: 5px 0; font-size: 14px;"><strong>📍 Dirección:</strong> ${punto.address}</p>
        <p style="margin: 5px 0; font-size: 14px;"><strong>📞 Teléfono:</strong> ${punto.phone}</p>
        <p style="margin: 5px 0; font-size: 14px;"><strong>🏢 Organización:</strong> ${punto.organization}</p>
        <p style="margin: 5px 0; font-size: 14px;"><strong>♻️ Materiales:</strong> ${punto.materials.join(', ')}</p>
        <p style="margin: 5px 0; font-size: 14px;"><strong>🕒 Horario:</strong> ${punto.schedule}</p>
        <p style="margin: 5px 0; font-size: 14px;"><strong>📏 Distancia:</strong> ${punto.distance.toFixed(1)} km</p>
        <div style="margin-top: 15px; display: flex; gap: 10px;">
          <button onclick="openDirections(${punto.lat}, ${punto.lng})" 
                  style="background: #22c55e; color: white; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; flex: 1;">
            <i class="fas fa-paper-plane"></i> Cómo llegar
          </button>
          <button onclick="callPhone('${punto.phone}')" 
                  style="background: #3b82f6; color: white; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; flex: 1;">
            <i class="fas fa-phone"></i> Llamar
          </button>
        </div>
      </div>
    `;
    
    marker.bindPopup(popupContent);
    markersGroup.addLayer(marker);
  });
}

// Obtener clase de icono según el tipo de punto
function getIconClass(type) {
  switch(type) {
    case 'empresas':
      return 'fas fa-building';
    case 'centros':
      return 'fas fa-shopping-cart';
    case 'universidades':
      return 'fas fa-graduation-cap';
    default:
      return 'fas fa-recycle';
  }
}

// Funciones globales para los botones de acción
window.openDirections = function(lat, lng) {
  const url = `https://www.google.com/maps/dir/?api=1&destination=${lat},${lng}`;
  window.open(url, '_blank');
};

window.callPhone = function(phone) {
  if (phone && phone !== 'No disponible') {
    window.location.href = `tel:${phone}`;
  } else {
    alert('Número de teléfono no disponible');
  }
};

window.showPointDetails = function(id) {
  const punto = puntosReciclaje.find(p => p.id === id);
  if (punto) {
    alert(`Detalles de ${punto.name}:\n\nDirección: ${punto.address}\nTeléfono: ${punto.phone}\nOrganización: ${punto.organization}\nMateriales: ${punto.materials.join(', ')}`);
  }
};

// Agregar estilos CSS para los marcadores personalizados
const mapStyles = `
  <style>
    .custom-marker-container {
      background: none !important;
      border: none !important;
    }
    .custom-marker {
      width: 30px;
      height: 30px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 14px;
      border: 2px solid white;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      cursor: pointer;
    }
    .custom-marker.empresas {
      background-color: #22c55e;
    }
    .custom-marker.centros {
      background-color: #3b82f6;
    }
    .custom-marker.universidades {
      background-color: #f59e0b;
    }
    .custom-marker:hover {
      transform: scale(1.1);
      transition: transform 0.2s;
    }
  </style>
`;

// Agregar estilos al head del documento
if (!document.querySelector('#map-custom-styles')) {
  const styleElement = document.createElement('div');
  styleElement.id = 'map-custom-styles';
  styleElement.innerHTML = mapStyles;
  document.head.appendChild(styleElement);
}