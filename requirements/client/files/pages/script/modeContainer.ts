const modeItems = [
  {
    title: 'VS AI',
    titleKey: 'AIVs',
    descriptionKey: 'aiModeDesc',
    image: 'assets/img/ai-mode.jpg',
    icon: 'fas fa-robot',
    bgColor: 'bg-blue-100',
    iconColor: 'text-blue-600',
    textColor: 'group-hover:text-blue-600',
    onClick: 'select_scene_AI()'
  },
  {
    title: '2 Players',
    titleKey: 'playersVs',
    descriptionKey: 'playersModeDesc',
    image: 'assets/img/2players-mode.jpg',
    icon: 'fas fa-users',
    bgColor: 'bg-green-100',
    iconColor: 'text-green-600',
    textColor: 'group-hover:text-green-600',
    onClick: 'showAliasPopup()'
  },
  {
    title: 'VS online players',
    titleKey: 'onlinePlayer',
    descriptionKey: 'onlineModeDesc',
    image: 'assets/img/online-mode.jpg',
    icon: 'fas fa-globe',
    bgColor: 'bg-purple-100',
    iconColor: 'text-purple-600',
    textColor: 'group-hover:text-purple-600',
    onClick: 'showOnlineLobbyPopup()'
  },
  {
    title: 'Tournament',
    titleKey: 'tournament',
    descriptionKey: 'tournamentModeDesc',
    image: 'assets/img/tournament-mode.png',
    icon: 'fas fa-trophy',
    bgColor: 'bg-yellow-100',
    iconColor: 'text-yellow-600',
    textColor: 'group-hover:text-yellow-600',
    onClick: 'showTournamentPopup()'
  }
];


const sceneItems = [
  {
    title: 'Pixel',
    titleKey: 'pixelScene',
    description: 'Pixel art style',
    image: 'assets/img/pixel-scene.png',
    icon: 'fa-solid fa-puzzle-piece',
    bgColor: 'bg-pink-100',
    iconColor: 'text-pink-600',
    textColor: 'group-hover:text-pink-600',
    onClick: 'load_pixel_game()'
  },
  {
    title: 'Arc',
    titleKey: 'arcScene',
    description: 'Arc art style ',
    image: 'assets/img/arc-scene.png',
    icon: 'fas fa-gamepad',
    bgColor: 'bg-teal-100',
    iconColor: 'text-teal-600',
    textColor: 'group-hover:text-teal-600',
    onClick: 'load_arc_game()'
  }
];

// Function to initialize the scene container
function initializeSceneContainer() {
  const sceneContainer = document.getElementById('scene-container');
  if (sceneContainer) {
    sceneContainer.innerHTML = '';
    
    const t = getLang();
    
    // Create and append each scene item
    sceneItems.forEach(item => {
      const sceneItemElement = document.createElement('div');
      sceneItemElement.innerHTML = `
        <div class="mode-item group" onclick="${item.onClick}">
          <div class="flex items-start space-x-4">
            <div class="flex-1">
              <img src="${item.image}" alt="${item.title}" class="mode-image">
              <div class="flex items-center space-x-2 bg-white shadow-lg">
                <div class="flex items-center justify-center m-4 ${item.bgColor} rounded-full w-[44px] h-[44px] flex-shrink-0">
                  <i class="${item.icon} ${item.iconColor} text-lg"></i>
                </div>
                <div class="flex-1 space-y-0">
                  <p class="${item.textColor}">${item.title}</p>
                  <p class="detail-mode">${item.description}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
      
      const element = sceneItemElement.firstElementChild;
      if (element) {
        sceneContainer.appendChild(element);
      }
    });
  }
}

// Function to initialize the mode container
function initializeModeContainer() {
  const modeContainer = document.getElementById('mode-container');
  if (modeContainer) {
    modeContainer.innerHTML = '';
    
    const t = getLang();
    
    // Create and append each mode item
    modeItems.forEach(item => {
      const modeItemElement = document.createElement('div');
      modeItemElement.innerHTML = `
        <div class="mode-item group" onclick="${item.onClick}">
          <div class="flex items-start space-x-4">
            <div class="flex-1">
              <img src="${item.image}" alt="${item.title}" class="mode-image">
              <div class="flex items-center space-x-2 bg-white shadow-lg">
                <div class="flex items-center justify-center m-4 ${item.bgColor} rounded-full w-[44px] h-[44px] flex-shrink-0">
                  <i class="${item.icon} ${item.iconColor} text-lg"></i>
                </div>
                <div class="flex-1 space-y-0">
                  <p class="${item.textColor}" data-i18n="${item.titleKey}">${t[item.titleKey] || item.title}</p>
                  <p class="detail-mode" data-i18n="${item.descriptionKey}">${t[item.descriptionKey]}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
      
      const element = modeItemElement.firstElementChild;
      if (element) {
        modeContainer.appendChild(element);
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', function() {
  initializeModeContainer();
  initializeSceneContainer();
});