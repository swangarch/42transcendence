type AlertButton = {
  text: string;
  onClick: (event?: MouseEvent) => void;
};

let customAlertStrictMode = false;

function showCustomAlertStrict(message: string, buttons: AlertButton[] = [
  { text: "OK", onClick: () => {} }]
) {
  customAlertStrictMode = true;
  const customAlert = document.getElementById('customAlert')!;
  const alertMessage = document.getElementById('alertMessage')!;
  const buttonsContainer = document.getElementById('alertButtons')!;

  alertMessage.textContent = message;
  buttonsContainer.innerHTML = '';

  buttons.forEach(({ text, onClick }) => {
    const btn = document.createElement('button');
    btn.textContent = text;
    btn.addEventListener('click', (event) => {
      onClick(event);
      customAlert.style.display = 'none';
      customAlertStrictMode = false;
    });
    buttonsContainer.appendChild(btn);
  });

  customAlert.style.display = 'flex';
}

function showCustomAlert(message: string, buttons: AlertButton[] = [
  { text: "OK", onClick: () => {} }]) {

  const customAlert = document.getElementById('customAlert')!;
  const alertMessage = document.getElementById('alertMessage')!;
  const buttonsContainer = document.getElementById('alertButtons')!;

  alertMessage.textContent = message;
  buttonsContainer.innerHTML = '';

  buttons.forEach(({ text, onClick }) => {
    const btn = document.createElement('button');
    btn.textContent = text;
    btn.addEventListener('click', (event) => {
      onClick(event);  // <-- passer l'event ici
      customAlert.style.display = 'none';
    });
    buttonsContainer.appendChild(btn);
  });

  customAlert.style.display = 'flex';
}

function hideCustomAlert() {
  const customAlert = document.getElementById('customAlert');
  if (customAlert) {
    customAlert.style.display = 'none';
  }
}

const customAlert = document.getElementById('customAlert');
if (customAlert) {
  customAlert.addEventListener('click', (event) => {
    // Ne ferme que si on n'est PAS en mode strict
    if (!customAlertStrictMode && event.target === customAlert) {
      hideCustomAlert();
    }
  });
}

// Alias management
function showAliasPopup() {
  const modal = document.getElementById('middleSetAlias');
  set_user_alias_1vs1();
  if (modal) {
    modal.style.display = 'flex';
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

function hideAliasPopup() {
  const modal = document.getElementById('middleSetAlias');
  if (modal) {
    modal.style.display = 'none';
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

// Online Lobby
function showOnlineLobbyPopup() {
  const modal = document.getElementById('vsOnlineView');
  if (modal) {
    modal.style.display = 'flex';
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

function hideOnlineLobbyPopup() {
  const modal = document.getElementById('vsOnlineView');
  if (modal) {
    modal.style.display = 'none';
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

const vsOnlineView = document.getElementById('vsOnlineView');
if (vsOnlineView) {
  vsOnlineView.addEventListener('click', (event) => {
    if (event.target === vsOnlineView) {
      hideOnlineLobbyPopup();
    }
  });
}

// Tournament Popup
function showTournamentPopup() {
  const overlay = document.getElementById('tournament-popup');
  if (overlay) {
    overlay.style.display = 'flex';
    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
  }
}

function hideTournamentPopup() {
  const overlay = document.getElementById('tournament-popup');
  if (overlay) {
    overlay.style.display = 'none';
    overlay.classList.add('hidden');
    overlay.classList.remove('flex');
  }
}

const tournamentPopup = document.getElementById('tournament-popup');
if (tournamentPopup) {
  tournamentPopup.addEventListener('click', (event) => {
    if (event.target === tournamentPopup) {
      hideTournamentPopup();
    }
  });
}


const aliasForm = document.getElementById('aliasForm') as HTMLFormElement | null;
if (aliasForm) {
  aliasForm.addEventListener('submit', (e) => {
    e.preventDefault();
    set_player_alias(e);
  });
}

const middleSetAlias = document.getElementById('middleSetAlias');
if (middleSetAlias) {
  middleSetAlias.addEventListener('click', (event) => {
    if (event.target === middleSetAlias) {
      hideAliasPopup();
    }
  });
}


// Next button
function createNextButtons(): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('button.nextBtn');
  
  buttons.forEach(button => {
    button.innerHTML = ''; 

    const divNext = document.createElement('div');
    divNext.className = 'div-next';
    divNext.setAttribute('data-i18n', 'nextBtn');
    divNext.textContent = 'Next';

    const divIcon = document.createElement('div');
    divIcon.className = 'div-next-icon';

    const icon = document.createElement('i');
    icon.className = 'fa-solid fa-arrow-right w-6 h-6 pt-2';

    divIcon.appendChild(icon);
    button.appendChild(divNext);
    button.appendChild(divIcon);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  createNextButtons();
});
