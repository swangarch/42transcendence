// Match history data (fetch)
type LeaderBoard = {
    alias: string;
    score: string;
};

var topClassement: LeaderBoard[] = [];

// Create an avatar circle with fallback
function createAvatarCircle(playerAlias: string, rank?: number): HTMLDivElement {
  const wrapper = document.createElement("div");
  wrapper.className = "flex items-center gap-1 w-16";

  // Rank display
  const rankDisplay = document.createElement("div");
  rankDisplay.className = "w-8 text-lg text-center";

  if (rank && rank >= 1 && rank <= 3) {
    if (rank === 1) 
      rankDisplay.textContent = "🥇";
    else if (rank === 2) 
      rankDisplay.textContent = "🥈";
    else if (rank === 3) 
      rankDisplay.textContent = "🥉";
  } else {
    rankDisplay.textContent = rank ? `#${rank}` : "";
  }
  wrapper.appendChild(rankDisplay);

  // Avatar
  const circle = document.createElement("div");
  circle.className = "w-8 h-8 rounded-full bg-gray-400 overflow-hidden flex-shrink-0 border-2 border-white ";

  const img = document.createElement("img");
  img.src = 'api/avatar/' + playerAlias;
  img.alt = "Avatar";
  img.className = "w-full h-full object-cover";
  // If the image fails to load, show a gray circle
  img.onerror = () => {
    img.style.display = "none";
    circle.classList.add("bg-gray-500");
  };

  circle.appendChild(img);
  wrapper.appendChild(circle);

  return wrapper;
}

// Create a complete player row with points
function createPlayerRow(rank: number, score: string): { row: HTMLDivElement, pointsSpan: HTMLSpanElement } {
  const row = document.createElement("div");
  const pointsSpan = document.createElement("span");
  
  if (rank === 1) {
    row.className = "leaderboard-container-1";
    pointsSpan.className = "leaderboard-points bg-yellow-400";
  } else if (rank === 2) {
    row.className = "leaderboard-container-2";
    pointsSpan.className = "leaderboard-points bg-gray-400";
  } else if (rank === 3) {
    row.className = "leaderboard-container-3";
    pointsSpan.className = "leaderboard-points bg-orange-400";
  } else {
    row.className = "leaderboard-container-all";
    pointsSpan.className = "leaderboard-points bg-indigo-300";
  }
  
  pointsSpan.textContent = score;
  return { row, pointsSpan };
}

// Show the current player below the leaderboard container
function showCurrentPlayer(container: HTMLElement, currentPlayer: LeaderBoard, currentPlayerRank: number) {
  const t = getLang();
  // Create a separate container for the current player below the main leaderboard
  const currentPlayerContainer = document.createElement("div");
  currentPlayerContainer.className = "my-2";
  currentPlayerContainer.id = "current-player-container";
  
  const separator = document.createElement("div");
  separator.className = "flex items-center justify-center my-2";
  separator.innerHTML = `
    <div class="flex-1 h-px"></div>
    <p class="text-xs text-gray-500">--------
      <span class="px-2 text-xs text-gray-500">${t.yourRank}</span>
      --------</p>
    <div class="flex-1 h-px"></div>
  `;
  currentPlayerContainer.appendChild(separator);
  
  const currentPlayerRow = document.createElement("div");
  currentPlayerRow.className = "rounded-full leaderboard-container-player";
  
  const currentAvatarWrapper = createAvatarCircle(currentPlayer.alias, currentPlayerRank);
  
  const currentContent = document.createElement("div");
  currentContent.className = "flex items-center w-full gap-2";
  
  const currentAliasSpan = document.createElement("span");
  currentAliasSpan.className = "text-sm mr-auto truncate font-bold text-gray-900";
  currentAliasSpan.textContent = currentPlayer.alias;
  
  const currentPointsSpan = document.createElement("span");
  currentPointsSpan.className = "text-sm ml-auto mr-[0.5rem] bg-blue-600 text-white px-2 py-1 rounded font-bold";
  currentPointsSpan.textContent = currentPlayer.score;
  
  currentContent.appendChild(currentAvatarWrapper);
  currentContent.appendChild(currentAliasSpan);
  currentContent.appendChild(currentPointsSpan);
  
  currentPlayerRow.appendChild(currentContent);
  currentPlayerContainer.appendChild(currentPlayerRow);
  
  container.appendChild(currentPlayerContainer);
}

// Show the leaderboard
async function showLeaderBoard() {
  const t = getLang();
  const container = document.getElementById("right-leaderboard");
  if (!container) return;

  container.innerHTML = "";

  const categories = document.createElement("div");
  
  categories.className = "flex justify-between items-center bg-gray-300 mb-1 p-2 rounded";
  categories.innerHTML = `
    <span class="text-sm ml-[2rem]">${t.leader}</span>
    <span class="text-sm mr-[0.5rem]">${t.points}</span>
  `;
  container.appendChild(categories);

  // If no matches, show a message
  if (topClassement.length === 0) {
    const noClassement = document.createElement("div");
    noClassement.className = "text-center text-gray-500";
    noClassement.textContent = `${t.noMatchFound || "No matches found."}`;
    container.appendChild(noClassement);
    return;
  }

  // Create rows for each top player
  const rows = document.createElement("div");
  rows.className = "flex flex-col overflow-y-auto h-full max-h-[18rem]";
  rows.id = "classement-rows";
  container.appendChild(rows);

  const classementRows = document.getElementById("classement-rows");
  if (!classementRows) {
    console.log("Element with id 'classement-rows' not found.");
    return;
  }
  
  // Sort topClassement by score 
  topClassement.sort((a, b) => parseInt(b.score) - parseInt(a.score));
  
  // Find the current player's rank and info
  const currentPlayerRank = topClassement.findIndex(player => player.alias === game.alias) + 1;
  const currentPlayer = topClassement.find(player => player.alias === game.alias);
  
  // Display top 10 players (without special treatment for current player)
  topClassement.forEach((classement, index) => {
    if (index >= 10) 
      return;
    
    const rank = index + 1;
    
    // Create the row and points span for the player
    const { row: playerRow, pointsSpan } = createPlayerRow(rank, classement.score);
    
    const avatarWrapper = createAvatarCircle(classement.alias, index + 1);

    const content = document.createElement("div");
    content.className = "flex items-center w-full gap-2";

    const aliasSpan = document.createElement("span");
    aliasSpan.className = "text-sm mr-auto truncate";
    aliasSpan.textContent = classement.alias;

    content.appendChild(avatarWrapper);
    content.appendChild(aliasSpan);
    content.appendChild(pointsSpan);

    playerRow.appendChild(content);
    classementRows.appendChild(playerRow);
  });
  
  // Always show the current player
  if (currentPlayer && currentPlayerRank > 0) {
    showCurrentPlayer(container, currentPlayer, currentPlayerRank);
  }
}

window.addEventListener("DOMContentLoaded", function () {
  showLeaderBoard();
});
