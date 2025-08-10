var allPlayers: PlayerTournament[] = [];

// Round names based on the number of players
const roundIds: Record<number, string> = {
  2: "final",
  4: "semi-finals",
  8: "quarter-finals",
  16: "round-of-16",
};

const roundNames: Record<LanguageCode, Record<string, string>> = {
  en: {
    "final": "Final (2 players)",
    "semi-finals": "Semi Finals (4 players)",
    "quarter-finals": "Quarter Finals (8 players)",
    "round-of-16": "Round of 16 (16 players)",
    "match": "Match",
  },
  fr: {
    "final": "Finale (2 joueurs)",
    "semi-finals": "Demi-finales (4 joueurs)",
    "quarter-finals": "Quarts de finale (8 joueurs)",
    "round-of-16": "Huitièmes de finale (16 joueurs)",
    "match": "Match",
  },
  zh: {
    "final": "决赛（2名玩家）",
    "semi-finals": "半决赛（4名玩家）",
    "quarter-finals": "四分之一决赛（8名玩家）",
    "round-of-16": "16强赛（16名玩家）",
    "match": "比赛", 
  },
};

function getRoundId(playerCount: number): string {
  return roundIds[playerCount] || `round-${playerCount}`;
}

function getRoundName(roundId: string): string {
  const lang = (localStorage.getItem("lang") as LanguageCode) || 'en';
  return roundNames[lang][roundId] || roundId;
}

interface PlayerTournament {
  name: string;
  played?: boolean;
  result?: boolean;
}

// Shuffle the players array
function shufflePlayers(players: PlayerTournament[]): PlayerTournament[] {
  console.log("Shuffling players:", players);
  for (let i = players.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [players[i], players[j]] = [players[j], players[i]];
  }
  allPlayers = players;
  return players;
}

// Create a player element for the tournament
function createTournamentPlayer(player: PlayerTournament | undefined, index: number, container: HTMLElement | null): HTMLDivElement {
  const div = document.createElement('div');
  div.className = 'tournament-player';

  if (player) {
    if (container) {
      div.id = `${container.id}-player-${player.name}`;
    }
    div.textContent = player.name;
  } else {
    div.classList.add('tournament-player-no-defined');
    div.textContent = 'No defined';
  }
  return div;
}

// Generate a tournament round with matches
function generateTournamentRound(players: PlayerTournament[], roundId: string, container: HTMLElement): void {
  const roundName = getRoundName(roundId);
  console.log(`Generating roundID: ${roundId}; Round name: ${roundName}`);
  // Create the round container
  const isLiveContainer = container.id === 'live-tournament-view';
  const roundDiv = document.createElement('div');
  roundDiv.className = isLiveContainer ? 'tournament-round' : 'tournament-round collapsed';
  roundDiv.id = `${container.id}-round-${roundId}`;

  const title = document.createElement('h2');
  title.className = 'tournament-round-title';
  title.dataset.roundId = roundId;
  title.textContent = roundName;
  roundDiv.appendChild(title);

  const roundContent = document.createElement('div');
  roundContent.className = 'tournament-round-content';
  roundDiv.appendChild(roundContent);
  container.appendChild(roundDiv);

  title.style.cursor = 'pointer';
  title.addEventListener('click', () => {
    roundDiv.classList.toggle('collapsed');
  });

  for (let i = 0; i < players.length; i += 2) {
    // console.log(`Processing match for players at index ${i} and ${i + 1}`);
    const player1 = players[i];
    const player2 = players[i + 1];

    const matchContainer = document.createElement('div');
    matchContainer.className = 'tournament-match-container';

    const matchName = document.createElement('div');
    matchName.className = 'tournament-match-name';
    matchName.dataset.matchIndex = String(i / 2 + 1);
    matchName.textContent = "";

    const matchDiv = document.createElement('div');
    const p1Div = createTournamentPlayer(player1, i, container);
    const p2Div = createTournamentPlayer(player2, i+1, container);

    const vs = document.createElement('div');
    vs.className = 'tournament-vs';
    vs.textContent = 'VS';

    matchDiv.appendChild(p1Div);
    matchDiv.appendChild(vs);
    matchDiv.appendChild(p2Div);

    matchContainer.appendChild(matchName);
    matchContainer.appendChild(matchDiv);
    roundContent.appendChild(matchContainer);
  }
}


// Generate the full tournament structure
function generateFullTournament(players: PlayerTournament[]): void {
  console.log("Generating full tournament with players:", players);

  const container = document.getElementById('tournament-rounds');
  const liveContainer = document.getElementById('live-tournament-view');
  
  if (!container) return;
  if (!liveContainer) return;

  let currentPlayers = players.map(p => ({
    name: p.name,
    played: false,
    result: false
  }));
  
  allPlayers = currentPlayers;
  const roundId = getRoundId(currentPlayers.length);
  (window as any).currentRoundId = roundId;

  const roundName = getRoundName(roundId);

  shufflePlayers(currentPlayers);

  generateTournamentRound(currentPlayers, roundId, container);
  generateTournamentRound(currentPlayers, roundId, liveContainer);
  updateTournamentLang();
}


// Initialize the tournament setup
function initTournament() {
  console.log("Initializing tournament...");

  // Get references to the HTML elements
  const playerCountInput = document.getElementById("player-count-input") as HTMLInputElement;
  const confirmPlayerCountBtn = document.getElementById("confirm-player-count")!;
  const playerAliasForm = document.getElementById("player-alias-inputs") as HTMLFormElement;
  const startTournamentBtn = document.getElementById("start-tournament-btn")!;
  const tournamentBracketContainer = document.getElementById("tournament-rounds")!;

  let tournamentPlayers: PlayerTournament[] = [];

  // Hide the tournament bracket and start button initially
  confirmPlayerCountBtn.addEventListener("click", () => {
    const count = parseInt(playerCountInput.value);
    // Validate the player count input
    if (![4, 8, 16].includes(count)) {
      return showCustomAlert("Only 4, 8, or 16 players allowed.");
    }
    playerAliasForm.innerHTML = "";
    playerAliasForm.classList.remove("hidden");
    playerAliasForm.classList.add("overflow-y-auto" ,"max-h-[400px]", "p-2");

    // Create input fields for player aliases
    for (let i = 0; i < count; i++) {
      const input = document.createElement("input");
      input.type = "text";
      input.name = `player-alias-${i}`;
      if (i === 0 && game.alias != undefined && game.alias.length > 0) {
        input.value = game.alias;
        input.required = true;
        input.disabled = true;
        input.className = "bg-gray-800 text-gray-300 disabled p-2 border rounded-[10px]";
      } else {
        // input.placeholder = `Player alias ${i + 1}`;
        input.dataset.playerIndex = String(i + 1);
        input.required = true;
        input.className = "p-2 border rounded-[10px]";
        const lang = (localStorage.getItem("lang") as LanguageCode) || 'en';
        const playerAliasLabel = translations[lang]["playerAlias"];
        input.placeholder = `${playerAliasLabel} ${i + 1}`;
      }
      playerAliasForm.appendChild(input);
    }

    startTournamentBtn.classList.remove("hidden");
  });

  // Handle the start tournament button click
  startTournamentBtn.addEventListener("click", () => {
    const inputs = playerAliasForm.querySelectorAll("input");
    tournamentPlayers = [];

    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i] as HTMLInputElement;
      const name = input.value.trim();
      if (!name) {
        return showCustomAlert("Every player must have an alias."); 
      }
      if (tournamentPlayers.some(player => player.name === name)) {
        return showCustomAlert(`Player alias "${name}" is already taken.`);
      }
      if (/\s/.test(name)) {
        return showCustomAlert(`Player alias cannot contain spaces.`);
      }
      if (name.length > 15) {
        return showCustomAlert(`Player alias is too long.`);
      }
      tournamentPlayers.push({
        name: name,
        played: false,
        result: false,
      });
    }
    tournamentBracketContainer.innerHTML = "";
    document.getElementById("live-tournament-view")!.innerHTML = "";
    generateFullTournament(tournamentPlayers);
    document.getElementById("button-tournament")?.classList.remove("hidden");
    navigate_to("tournamentView");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTournament();
});

// Synchronize the live tournament view 
function syncLiveToTournamentView(): void {
  const live = document.getElementById("live-tournament-view");
  const tournament = document.getElementById("tournament-rounds");

  if (live && tournament) {
    tournament.innerHTML = live.innerHTML;
    
    // Remove all the collapsed in tournament view
    const mainViewRounds = tournament.querySelectorAll('.tournament-round');
    mainViewRounds.forEach(round => {
      round.classList.remove('collapsed');
    });
  }
}

// Update match display with unified logic for ongoing and played states
function updateMatchDisplay(currentMatchIndex: number, currentRoundId: string, updateType: 'ongoing' | 'played'): void {
    const rounds = document.querySelectorAll('.tournament-round');
    rounds.forEach(round => {
        // Compare id with round (ex: "tournament-rounds-round-final")
        if (round.id.endsWith(currentRoundId)) {
            const matches = round.querySelectorAll('.tournament-match-container');
            
            if (updateType === 'ongoing') {
                matches.forEach((match, index) => {
                    if (index < currentMatchIndex) {
                        match.classList.remove('tournament-match-container-ongoing');
                        match.classList.add('tournament-match-container-played');
                    }
                    if (index === currentMatchIndex) {
                        match.classList.add('tournament-match-container-ongoing');
                    }
                });
            } else if (updateType === 'played') {
                if (currentMatchIndex >= matches.length) {
                    const lastMatch = matches[matches.length - 1];
                    lastMatch?.classList.remove('tournament-match-container-ongoing');
                    lastMatch?.classList.add('tournament-match-container-played');
                }
            }
        }
    });
}

// Update player display by names or player objects
function updatePlayersDisplay(playersData: PlayerTournament[] | string[], containerId: string = 'live-tournament-view'): void {
  const currentRound = (window as any).currentRoundId;
  
  if (Array.isArray(playersData) && playersData.length === 0) {
    console.log("No players data provided");
    return;
  }

  // Handle both PlayerTournament[] and string[] inputs
  if (typeof playersData[0] === 'string') {
    // Convert string names to PlayerTournament objects
    const playerNames = playersData as string[];
    for (const name of playerNames) {
      const player = allPlayers.find(p => p.name === name);
      if (player) {
        updatePlayerColor(containerId, player);
      }
    }
  } else {
    // Handle PlayerTournament[] directly
    const players = playersData as PlayerTournament[];
    for (const player of players) {
      updatePlayerColor(containerId, player);
    }
  }
}

// Legacy function - now uses unified logic  
function updateCurrentMatchDisplay(player1Name: string, player2Name: string): void {
  updatePlayersDisplay([player1Name, player2Name], 'live-tournament-view');
}

// Function to handle game end - update player results and colors
function updatePlayerResults(winner: string): void {
    const matchPlayer1 = currentTournamentMatch.player1;
    const matchPlayer2 = currentTournamentMatch.player2;
    let currentMatchPlayers: string[] = [];
        
    // Update player results and mark them as played
    for (let player of allPlayers) {
        if (player.name === matchPlayer1 || player.name === matchPlayer2) {
            if (player.name === winner) {
                player.result = true;
                player.played = true;
                currentMatchPlayers.push(player.name);
                nextRoundBuffer.push({
                    name: player.name,
                    played: false,
                    result: false,
                });
            } else {
                player.result = false;
                player.played = true;
                currentMatchPlayers.push(player.name);
            }
        }
    }
    
    // Update visual colors
    if (currentMatchPlayers.length >= 2) {
        updateCurrentMatchDisplay(currentMatchPlayers[0], currentMatchPlayers[1]);
    } 
}

// Update the player's color in the tournament display based on their result
function updatePlayerColor(containerId: string, player: PlayerTournament): void {
  const roundId = (window as any).currentRoundId;
  const roundContainer = document.getElementById(`${containerId}-round-${roundId}`);
  
  if (!roundContainer) return;

  const playerSelector = `#${containerId}-player-${player.name}`;
  const playerDiv = roundContainer.querySelector(playerSelector);
  
  if (!playerDiv) return;

  // Reset all state classes
  const stateClasses = ['tournament-player-winner', 'tournament-player-loser', 'tournament-player-no-defined'];
  playerDiv.classList.remove(...stateClasses);
  
  // Apply appropriate class based on player state
  if (player.played || (player.result !== undefined && player.result !== null)) {
    const resultClass = player.result === true ? 'tournament-player-winner' : 'tournament-player-loser';
    playerDiv.classList.add(resultClass);
  } 
}

// Update the match banner with the current and next matches
function updateMatchBanner(): void {
  const player1 = allPlayers[match_number]?.name || "";
  const player2 = allPlayers[match_number + 1]?.name || "";
  const player3 = allPlayers[match_number + 2]?.name || "";
  const player4 = allPlayers[match_number + 3]?.name || "";

  const bannerContent = document.getElementById("next-match-banner-content");
  if (!bannerContent) return;
  bannerContent.innerHTML = "";

  // Récupérer la langue courante
  const t = getLang();
  const roundKey = (window as any).currentRoundId || "nextRound";

  let text = "";

  if (roundKey === "final") {
    text = `<span>${t.final}</span>`;
  } else if (player1 && player2) {
    text = `<span>${t.currentMatch} :</span>`;
    text += `<span class="ml-2"><u>${player1}</u></span> VS <span class="mr-2"><u>${player2}</u></span>`;
    text += ` - `;
    text += `<span>${t.nextMatch} :</span> `;
    if (player3 && player4) {
      text += `<span class="ml-2"><u>${player3}</u></span> VS <span class="mr-2"><u>${player4}</u></span>`;
    } else {
      text += `<span>${t.waitNextRound}</span>`;
    }
  }

  const bannerWrapper = document.createElement("div");
  bannerWrapper.className = "flex animate-slide";

  for (let i = 0; i < 10; i++) {
    const span = document.createElement("span");
    span.className = "mr-16 whitespace-nowrap";
    span.innerHTML = text;
    bannerWrapper.appendChild(span);
  }
  bannerContent.appendChild(bannerWrapper);
}

// Winner effect management
function manageWinnerEffect(action: 'show' | 'hide', winner?: string, count?: number): void {
  const winnerResult = document.getElementById("winnerResult");
  if (!winnerResult) return;
  
  if (action === 'hide' || (count !== undefined && count <= 0)) {
    winnerResult.classList.add("hidden");
    winnerResult.innerHTML = "";
  } else if (action === 'show' && winner) {
    const t = getLang();
    winnerResult.classList.remove("hidden");
    winnerResult.innerHTML = `<span class="text-6xl">${t.winner}: </span>`;
    winnerResult.innerHTML += `${winner}`;
    winnerResult.classList.remove("winner");
    void winnerResult.offsetWidth;
    winnerResult.classList.add("winner");
  }
}

// Button next, start tournament game
document.getElementById("next-round-button")?.addEventListener("click", () => {
    document.getElementById("next-round-button")?.classList.add("hidden");

    if (allPlayers.length >= 2) {
        const player1 = allPlayers[match_number].name;
        const player2 = allPlayers[match_number + 1].name;
        tournament_create_game(player1, player2);
        tournament_start_game(player1, player2);

        setPlayersDisplay(player1, player2);
        match_number += 2;
    } else {
        isTournament = "end";
    }
});