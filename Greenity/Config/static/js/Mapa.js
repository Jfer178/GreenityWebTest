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
  const pointCards = document.querySelectorAll(".point-card");
  const actionBtns = document.querySelectorAll(".action-btn");

  // Estado de la aplicación
  let currentView = "list";
  let currentFilters = {
    distance: 1,
    materials: [],
    schedules: [],
  };

  // Inicialización
  init();

  function init() {
    setupDistanceSlider();
    setupCheckboxes();
    setupViewControls();
    setupMapControls();
    setupPointCards();
    setupActionButtons();
    setTimeout(initLeafletMap, 100);
    console.log("Mapa de reciclaje cargado correctamente");
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
    materialCheckboxes.forEach((checkbox) => {
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

    scheduleCheckboxes.forEach((checkbox) => {
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
    pointCards.forEach((card) => {
      let show = true;

      // Filtrar por materiales
      if (currentFilters.materials.length > 0) {
        const materials = Array.from(card.querySelectorAll(".material-tag"))
          .map((tag) => tag.textContent.toLowerCase());
        const hasMaterial = currentFilters.materials.some((filter) =>
          materials.some((material) => material.includes(filter))
        );
        if (!hasMaterial) show = false;
      }

      // Filtrar por horarios
      if (currentFilters.schedules.length > 0) {
        const schedule = card.querySelector(".point-schedule span").textContent.toLowerCase();
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
  }

  // Event listener para aplicar filtros
  if (applyFiltersBtn) {
    applyFiltersBtn.addEventListener("click", applyFilters);
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
  var map = L.map("map").setView([10.9639, -74.7964], 13);
  window.leafletMap = map;

  // Forzar redimensionamiento del mapa
  setTimeout(() => map.invalidateSize(), 250);

  // Añadir tiles de OpenStreetMap
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19,
    attribution: "© OpenStreetMap contributors",
  }).addTo(map);

  // Puntos de reciclaje
  var puntosReciclaje = [
    {
      name: "EcoPunto El Prado",
      lat: 10.9685,
      lng: -74.7813,
      address: "Cra. 54 #70-174, El Prado",
      materials: ["Plástico", "Papel", "Vidrio", "Metal"]
    },
    {
      name: "Centro de Acopio Norte", 
      lat: 10.9780,
      lng: -74.7890,
      address: "Calle 84 #43-50, Riomar",
      materials: ["Papel", "Cartón", "Pilas", "Electrónicos"]
    },
    {
      name: "Punto Verde Atlántico",
      lat: 10.9520,
      lng: -74.8020,
      address: "Cra. 38 #84-30, Atlántico", 
      materials: ["Orgánicos", "Plástico", "Vidrio"]
    }
  ];

  // Agregar marcadores
  puntosReciclaje.forEach(function(punto) {
    var marker = L.marker([punto.lat, punto.lng]).addTo(map);
    var popupContent = `
      <div style="min-width: 200px;">
        <h3 style="color: #22c55e; margin: 0 0 10px 0;">${punto.name}</h3>
        <p style="margin: 5px 0;"><strong>📍:</strong> ${punto.address}</p>
        <p style="margin: 5px 0;"><strong>♻️:</strong> ${punto.materials.join(', ')}</p>
        <button onclick="window.open('https://www.google.com/maps/dir/?api=1&destination=${punto.lat},${punto.lng}', '_blank')" 
                style="background: #22c55e; color: white; border: none; padding: 8px 12px; border-radius: 4px; margin-top: 10px; cursor: pointer;">
          Cómo llegar
        </button>
      </div>
    `;
    marker.bindPopup(popupContent);
  });

  console.log('Mapa de Leaflet inicializado correctamente');
}