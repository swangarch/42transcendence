// Match history data (fetch)
type Match = {
  id: number;
  opponent: string;
  score: string;
  date: string;
  type: "1v1" | "tournament" | "AI_Bot";
  result: "win" | "loss";
};

var matches: Match[] = [
];

// Format date to a more readable format
function formatDate(dateStr: string): string {
  const date = new Date(dateStr);
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  return `${year}/${month}/${day}`;
}

// Fetch match history from the server
function createTable(container: HTMLElement, titleText: string, matchList: Match[]) {
  if (matchList.length === 0) return;

  const t = getLang();

  // Crée un conteneur pour chaque table
  const tableWrapper = document.createElement("div");
  tableWrapper.className = "match-table-wrapper mb-12 w-full";

  // Détermine l'icône selon le type de match
  let typeIcon = "fa-solid fa-gamepad";
  if (matchList.length > 0) {
    const type = matchList[0].type;
    if (type === "1v1") {
      typeIcon = "fas fa-user-friends";
    } else if (type === "tournament") {
      typeIcon = "fas fa-trophy";
    } else if (type === "AI_Bot") {
      typeIcon = "fas fa-robot";
    }
  }

  const title = document.createElement("div");
  title.className = "header-title flex items-center gap-2 mx-4 mx-auto";
  title.innerHTML = `
    <i class=\"${typeIcon} mr-2 text-sm\"></i>
    <h2 class=\"text-xl font-bold\">${titleText}</h2>
  `;
  tableWrapper.appendChild(title);

  // Sort match list by date (newest first)
  matchList.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  // Header
  const header = document.createElement("div");
  header.className = "uppercase grid grid-cols-5 gap-2 font-semibold bg-gray-200 text-sm px-4 py-2 rounded-t-lg text-left w-full";
  header.innerHTML = `
    <div class="col-span-1 w-full flex items-center text-left">
      <i class="fas fa-calendar-alt mr-1 text-gray-500"></i>${t.date}
    </div>
    <div class="col-span-1 w-full flex items-center text-left">
      <i class="fas fa-user mr-1 text-gray-500"></i>${t.opponent}
    </div>
    <div class="col-span-1 w-full flex items-center text-left">
      <i class="fas fa-tags mr-1 text-gray-500"></i>${t.type}
    </div>
    <div class="col-span-1 w-full flex items-center text-left">
      <i class="fas fa-chart-line mr-1 text-gray-500"></i>${t.score}
    </div>
    <div class="col-span-1 w-full flex items-center text-left">
      <i class="fas fa-trophy mr-1 text-gray-500"></i>${t.result}
    </div>
  `;
  tableWrapper.appendChild(header);

  // Content rows
  matchList.forEach((match) => {
    const row = document.createElement("div");
    row.className = `
      grid grid-cols-5 gap-2 px-4 py-2 text-sm text-left
      ${match.result === "win" ? "bg-green-100 text-green-900" : "bg-red-100 text-red-900"}
      border-t border-gray-100 w-full
    `;
    // Icon and translation for type
    let typeLabel: string = match.type;
    if (match.type === "1v1") {
      typeLabel = t.type1v1 || t.type;
    } else if (match.type === "tournament") {
      typeLabel = t.typeTournament || t.type;
    } else if (match.type === "AI_Bot") {
      typeLabel = t.typeAI || t.type;
    }
    // Icon and translation for result
    let resultIcon = match.result === "win" ? "fas fa-crown" : "fas fa-times-circle";
    let resultLabel: string = match.result === "win" ? t.win : t.loss;

    row.innerHTML = `
      <div class="col-span-1 w-full flex items-center text-left">${formatDate(match.date)}</div>
      <div class="col-span-1 w-full flex items-center text-left">${match.opponent}</div>
      <div class="col-span-1 w-full flex items-center text-left">
        ${typeLabel}
      </div>
      <div class="col-span-1 w-full flex items-center text-left">${match.score}</div>
      <div class="col-span-1 w-full flex items-center text-left">
      <i class='${resultIcon} mr-1'></i>${resultLabel}</div>
    `;
    tableWrapper.appendChild(row);
  });

  container.appendChild(tableWrapper);
}

// Render match tables
function renderMatchTables(matches: Match[]) {
  const t = getLang();
  
  const container = document.getElementById("match-history");
  if (!container) {
    return console.log("Div 'match-history' not found.");
  }
  container.innerHTML = "";

  // Filter matches by type
  const match1v1 = matches.filter(m => m.type === "1v1");
  const matchTournament = matches.filter(m => m.type === "tournament");
  const matchAI = matches.filter(m => m.type === "AI_Bot");

  // Create tables for each match type
  createTable(container, t.match1v1 || "Matchs 1v1", match1v1);
  createTable(container, t.matchTournament || "Matchs Tournament", matchTournament);
  createTable(container, t.matchAI || "Matchs vs IA", matchAI);

  console.log("Table added to container.");
}

// Show match history
function updateMatchHistory() {
  // console.log("test");
  console.log("Show match history called.");
  renderMatchTables(matches);
}

function showMatchHistory() {
  // console.log("test");
  console.log("Show match history called.");
  renderMatchTables(matches);
  navigate_to('match-history-container')
}

// Ensure the script runs after the page is fully loaded
document.addEventListener("DOMContentLoaded", () => {
  (window as any).showMatchHistory = function () {
    renderMatchTables(matches);
    navigate_to('match-history-container');
    document.getElementById("match-history-container")!.style.display = "block";
  };
});

// Show reduced match table
function showReducedMatchTable() {
  const t = getLang();

  const container = document.getElementById("right-match-history");
  if (!container) return;

  container.innerHTML = "";

  const categories = document.createElement("div");
  categories.className = "flex justify-between items-center bg-gray-300 mb-1 p-2 rounded";

	categories.innerHTML = `
    <span class="text-sm font-semibold text-gray-700 ml-[0.5rem]">${t.alias}</span>
    <span class="text-sm font-semibold text-gray-700 mr-[0.5rem]">${t.result}</span>
    `;
  container.appendChild(categories);

	if (matches.length === 0) {
		const noMatches = document.createElement("div");
		noMatches.className = "text-center text-gray-500";
		noMatches.textContent = `${t.noMatchFound || "No matches found."}`;
		container.appendChild(noMatches);
		return;
	}

	const rows = document.createElement("div");
	rows.className = "flex flex-col overflow-y-auto h-full max-h-[23rem]";
	rows.id = "match-history-rows";
	container.appendChild(rows);

	const matchHistoryRows = document.getElementById("match-history-rows");
	if (!matchHistoryRows) {
		console.log("Element with id 'match-history-rows' not found.");
		return;
	}

  matches.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  matches.forEach((match, index) => {
    const row = document.createElement("div");
		if (index >= 10) return;
    
    // Use new match history container classes based on result
    const containerClass = match.result === "win" ? "match-history-container-win" : "match-history-container-loss";
    row.className = containerClass;
    
    row.onclick = () => showMatchPopup(match);
		row.onmouseenter = () => showMatchPopup(match);
    row.onmouseleave = closeMatchPopup;

    row.innerHTML = `
      <span class="ml-[0.5rem] text-sm truncate">${match.opponent}</span>
      <span class="${match.result === "win" ? "match-history-result-win" : "match-history-result-loss"}">
        ${match.result === "win" ? t.win : t.loss}
      </span>
    `;
    matchHistoryRows.appendChild(row);
		container.appendChild(matchHistoryRows);
  });
}

function showMatchPopup(match: Match) {
  const t = getLang();
  const popup = document.getElementById("match-popup");
  const content = document.getElementById("popup-content");

  if (!popup || !content) return;

  const resultColorClass = match.result === "win" ? "match-popup-win-color" : "match-popup-loss-color";
  const resultBgClass = match.result === "win" ? "match-popup-win-bg" : "match-popup-loss-bg";
  const resultIcon = match.result === "win" ? "fas fa-trophy" : "fas fa-times-circle";

  content.innerHTML = `
    <div class="match-popup-container">
      <!-- Header -->
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-2">
          <div class="p-2 bg-slate-700/50 rounded-lg">
            <i class="fas fa-gamepad text-blue-400 text-lg"></i>
          </div>
          <div>
            <h3 class="match-popup-title">${t.matchDetails}</h3>
            <p class="match-popup-date">${formatDate(match.date)}</p>
          </div>
        </div>
      </div>

      <!-- Match Info -->
      <div class="space-y-2 mb-4">
        <div class="match-popup-info-row">
          <span class="match-popup-info-label">
            <i class="fas fa-user match-popup-icon"></i> ${t.opponent}
          </span>
          <span class="match-popup-info-value">${match.opponent}</span>
        </div>
        
        <div class="match-popup-info-row">
          <span class="match-popup-info-label">
            <i class="fas fa-chart-line match-popup-icon"></i> ${t.score}
          </span>
          <span class="match-popup-info-value">${match.score}</span>
        </div>
        
        <div class="match-popup-info-row">
          <span class="match-popup-info-label">
            <i class="fas fa-tags match-popup-icon"></i> ${t.type}
          </span>
          <span class="match-popup-info-value">${match.type}</span>
        </div>
      </div>

      <!-- Result -->
      <div class="match-popup-result-container">
        <div class="match-popup-result-badge ${resultBgClass}">
          <i class="${resultIcon} ${resultColorClass} text-lg"></i>
          <div>
            <div class="match-popup-result-text">${t.result}</div>
            <div class="match-popup-result-value ${resultColorClass}">
              ${match.result === "win" ? t.win : t.loss}
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
  popup.classList.remove("hidden");
}

function closeMatchPopup() {
  const popup = document.getElementById("match-popup");
  if (popup) popup.classList.add("hidden");
}

// Initialize match history when DOM is loaded
window.addEventListener("DOMContentLoaded", function () {
  showReducedMatchTable();
});
