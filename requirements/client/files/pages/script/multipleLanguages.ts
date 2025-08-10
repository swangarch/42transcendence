// Types
type LanguageCode = 'en' | 'fr' | 'zh';

type TranslationDict = Record<LanguageCode, Record<string, string>>;

// Traductions
const translations: TranslationDict = {
  en: {
    // Navigation & Auth
    login: "Login",
    signUp: "Sign up",
    createAccount: "Create account !",
    logOut: "Log out",
    logOutConfirm: "Are you sure you want to log out?",
    yesLogOut: "Yes, log out",
    cancel: "Cancel",
    needLogin: "Please login!",
    returnMainPageConfirm: "Return to main page? Current game will be stopped.",
    yesReturn: "Yes, return",
    mainPage: "Main page",
    twoFactorAuth: "Two-factor authentication",
    enter2FACode: "Enter your 2FA code",
    checkAuthApp: "Check your authentication app",
    loginFailed: "Login failed",
    loginFailedMsg: "Login failed, please retry!",
    retry: "Retry",
    profilePicture: "Profile Picture",
    clickToUpload: "Click on image to upload",
    
    // Profile / User
    account: "Account",
    accountSetting: "Account Settings",
    username: "Username",
    password: "Password",
    alias: "Alias",
    userCard: "User card",
    yourRank: "Your rank",
    playerAlias: "Player alias",
    friends: "Friends",
    noFriends: "No friends yet",
    addFriends: "Add Friends",
    friendPending: "Request pending",
    friendAccepted: "Request accepted",
    friendRejected: "Request rejected",

    // Two-Factor Authentication
    faToggle: "Two-factor authentication (on going)",
    faAuth: "Two-Factor Authentication (2FA)",
    loadingTwoFaStatus: "Loading 2FA status...",
    enabled: "Enabled",
    disabled: "Disabled",
    faEnabled: "2FA is ENABLED",
    faDisabled: "2FA is DISABLED",
    disable2FA: "Disable 2FA",
    twofaInputPrompt: "Please enter your 6-digit 2FA code to disable 2FA:",
    scanQRCode: "Scan this QR code with your authenticator app",
    setup2FA: "Setup 2FA",
    enterSetupCode: "Then enter the 6-digit code:",
    
    // Buttons / Actions
    returnBtn: "Return",
    nextBtn: "Next",
    validBtn: "Validate",
    retryBtn: "Retry",
    start: "Start",
    stop: "Stop",
    invitePlayer: "Invite player",
    sendInvitation: "Invite",
    findPlayer: "Find player",
    enterUsername: "Enter username...",
    saveChanges: "Save Changes",
    backToGame: "Back to Game",
    deleteUser: "Delete user",
    addNewFriend: "Add new friend",
    verifyBtn: "Verify",
    cancelBtn: "Cancel",
    confirmBtn: "Confirm",

    // Game / Modes
    chooseMode: "Game mode",
    chooseScene: "Choose your scene",
    chooseOpponent: "Choose your opponent",
    AIVs: "VS AI",
    playersVs: "2 Players",
    onlinePlayer: "VS online players",
    setAlias: "Set player alias",
    gamePlay: "Game play",
    onlineLobby: "Online Lobby",
    
    // Mode descriptions
    aiModeDesc: "Challenge our smart AI opponent",
    playersModeDesc: "Play locally with a friend",
    onlineModeDesc: "Face players from around the world",
    tournamentModeDesc: "Compete in bracket-style matches",
    
    // Tournament
    tournament: "Tournament",
    startTournament: "Start tournament",
    nbrPlayer: "Number of players: ",
    final: "Final !",
    waitNextRound: "Wait for the next round...",
    classement: "Top ranking",
    leader: "Leader",
    points: "Points",
    
    // Match / History
    matchHistory: "Match history",
    matchHistoryLast: "Last 10 matches",
    currentMatch: "Current match",
    nextMatch: "Next match",
    noMatchHistory: "No match history.",
    noMatchFound: "No matches found.",
    matchDetails: "Match details",
    winner: "Winner",
    player1: "Player 1",
    player2: "Player 2",
    type1v1: "1v1",
    typeTournament: "Tournament",
    typeAI: "AI Bot",
    match1v1: "1v1 Matches",
    matchTournament: "Tournament Matches",
    matchAI: "AI Matches",
    
    // Game
    racketUseText: "Use these keys to control your racket",

    // Stats / Misc
    score: "Score",
    rank: "Rank",
    rate: "Rate",
    date: "Date",
    opponent: "Opponent",
    type: "Type",
    result: "Result",
    win: "Win",
    loss: "Loss",
    matches: "Matches",
    wins: "Wins",
    losses: "Losses",

    // Friend Info
    recentMatches: "Recent Matches",
    loading: "Loading...",
    failedToLoad: "Failed to load friend info",
    totalMatches: "Total Matches",
    winRate: "Win Rate",
    inviteToGame: "Invite to Game",
    online: "Online",
    offline: "Offline",
  },
  fr: {
    // Navigation & Auth
    login: "Connexion",
    signUp: "S'inscrire",
    createAccount: "Créer un compte !",
    logOut: "Déconnexion",
    logOutConfirm: "Êtes-vous sûr de vouloir vous déconnecter ?",
    yesLogOut: "Oui, se déconnecter",
    cancel: "Annuler",
    needLogin: "Veuillez vous connecter !",
    returnMainPageConfirm: "Retourner à la page principale ? Le jeu en cours sera arrêté.",
    yesReturn: "Oui, retourner",
    mainPage: "Page principale",
    twoFactorAuth: "Authentification à deux facteurs",
    enter2FACode: "Entrez votre code 2FA",
    checkAuthApp: "Vérifiez votre application d'authentification",
    loginFailed: "Échec de la connexion",
    loginFailedMsg: "Échec de la connexion, veuillez réessayer !",
    retry: "Réessayer",
    profilePicture: "Photo de profil",
    clickToUpload: "Cliquez sur l'image pour télécharger",

    // Profil / Utilisateur
    account: "Compte",
    accountSetting: "Paramètres du compte",
    username: "Nom d'utilisateur",
    password: "Mot de passe",
    alias: "Alias",
    userCard: "Carte utilisateur",
    yourRank: "Votre rang",
    playerAlias: "Alias du joueur",
    friends: "Amis",
    noFriends: "Aucun ami pour le moment",
    addFriends: "Ajouter des amis",
    friendPending: "Demande en attente",
    friendAccepted: "Demande acceptée",
    friendRejected: "Demande rejetée",

    // Authentification à deux facteurs
    faToggle: "Authentification à deux facteurs (en cours)",
    faAuth: "Authentification à deux facteurs (2FA)",
    loadingTwoFaStatus: "Chargement du statut 2FA...",
    enabled: "Activé",
    disabled: "Désactivé",
    faEnabled: "2FA est ACTIVÉE",
    faDisabled: "2FA est DÉSACTIVÉE",
    disable2FA: "Désactiver 2FA", 
    twofaInputPrompt: "Veuillez entrer votre code 2FA à 6 chiffres pour désactiver 2FA :",
    scanQRCode: "Scannez ce code QR avec votre application d'authentification",
    setup2FA: "Configurer 2FA",
    enterSetupCode: "Puis entrez le code à 6 chiffres :",

    // Boutons / Actions
    returnBtn: "Retour",
    nextBtn: "Suivant",
    validBtn: "Valider",
    retryBtn: "Réessayer",
    start: "Démarrer",
    stop: "Arrêter",
    invitePlayer: "Inviter un joueur",
    sendInvitation: "Inviter",
    findPlayer: "Trouver un joueur",
    enterUsername: "Entrez le nom d'utilisateur...",
    saveChanges: "Enregistrer les modifications",
    backToGame: "Retourner au jeu",
    deleteUser: "Supprimer l'utilisateur",
    addNewFriend: "Ajouter un nouvel ami",
    verifyBtn: "Vérifier",
    cancelBtn: "Annuler",
    confirmBtn: "Confirmer",

    // Jeu / Modes
    chooseMode: "Mode du jeu",
    chooseScene: "Scène du jeu",
    chooseOpponent: "Choisissez un adversaire",
    AIVs: "VS AI",
    playersVs: "2 joueurs",
    onlinePlayer: "VS joueurs en ligne",
    setAlias: "Définir l'alias du joueur",
    gamePlay: "Jouer",
    onlineLobby: "Salle en ligne",

    // Descriptions des modes
    aiModeDesc: "Défiez notre IA intelligente",
    playersModeDesc: "Jouez localement avec un ami",
    onlineModeDesc: "Affrontez des joueurs du monde entier",
    tournamentModeDesc: "Participez à des matchs en tournoi",

    // Tournoi
    tournament: "Tournoi",
    startTournament: "Démarrer le tournoi",
    nbrPlayer: "Nombre de joueurs : ",
    final: "Finale !",
    waitNextRound: "Attendre le prochain tour...",
    classement: "Top classement",
    leader: "Premiers",
    points: "Points",

    // Match / Historique
    matchHistory: "Historique des matchs",
    matchHistoryLast: "10 derniers matchs",
    currentMatch: "Match actuel",
    nextMatch: "Prochain match",
    noMatchHistory: "Aucun historique de match.",
    noMatchFound: "Aucun match trouvé.",
    matchDetails: "Détails du match",
    winner: "Gagnant",
    player1: "Joueur 1",
    player2: "Joueur 2",
    tournamentNumber: "Seulement 4, 8, 16",
    type1v1: "1v1",
    typeTournament: "Tournoi",
    typeAI: "IA",
    match1v1: "Matchs 1v1",
    matchTournament: "Matchs Tournoi",
    matchAI: "Matchs IA",

    // Jeu
    racketUseText: "Utilisez ces touches pour contrôler votre raquette",

    // Statistiques / Divers
    score: "Score",
    rank: "Rang",
    rate: "Taux",
    date: "Date",
    opponent: "Adversaire",
    type: "Type",
    result: "Résultat",
    win: "Gagné",
    loss: "Perdu",
    matches: "Matchs",
    wins: "Gagnés",
    losses: "Perdus",

    // Info ami
    recentMatches: "Matchs récents",
    loading: "Chargement...",
    failedToLoad: "Échec de chargement ami",
    totalMatches: "Matchs totaux",
    winRate: "Taux de victoire",
    inviteToGame: "Inviter un ami à jouer",
    online: "En ligne",
    offline: "Hors ligne",
  },
  zh: {
    // 导航 & 认证
    login: "登录",
    signUp: "注册",
    createAccount: "创建用户！",
    logOut: "退出",
    logOutConfirm: "确定要退出吗？",
    yesLogOut: "是的，退出",
    cancel: "取消",
    needLogin: "请登录！",
    returnMainPageConfirm: "返回主页？ 当前游戏将被停止。",
    yesReturn: "是的，返回",
    mainPage: "主页",
    twoFactorAuth: "双重认证",
    enter2FACode: "输入您的2FA代码",
    checkAuthApp: "检查您的认证应用",
    loginFailed: "登录失败",
    loginFailedMsg: "登录失败，请重试！",
    retry: "重试",
    profilePicture: "个人头像",
    clickToUpload: "点击图片上传",

    // 个人/用户
    account: "账号",
    accountSetting: "账号设置",
    username: "用户名",
    password: "密码",
    alias: "别名",
    userCard: "用户卡片",
    yourRank: "你的排名",
    playerAlias: "玩家别名",
    friends: "好友",
    noFriends: "没有好友",
    addFriends: "添加好友",
    friendPending: "请求待处理",
    friendAccepted: "请求已接受",
    friendRejected: "请求已拒绝",

    // 双重认证
    faToggle: "双重认证(进行中)",
    faAuth: "双重认证(2FA)",
    loadingTwoFaStatus: "加载2FA状态中...",
    enabled: "已启动",
    disabled: "已关闭",
    faEnabled: "2FA已启用",
    faDisabled: "2FA已关闭",
    disable2FA: "关闭2FA",
    twofaInputPrompt: "请输入您的6位数2FA代码以关闭2FA：",
    scanQRCode: "使用您的认证应用扫描此二维码",
    setup2FA: "设置2FA",
    enterSetupCode: "然后输入6位数代码：",

    // 按钮/操作
    returnBtn: "返回",
    nextBtn: "继续",
    validBtn: "确认",
    retryBtn: "重试",
    start: "开始",
    stop: "停止",
    invitePlayer: "邀请",
    sendInvitation: "发送邀请",
    findPlayer: "找玩家",
    enterUsername: "输入用户名...",
    saveChanges: "保存修改",
    deleteUser: "删除用户",
    backToGame: "返回游戏",
    verifyBtn: "验证",
    cancelBtn: "取消",
    confirmBtn: "确认",

    // 游戏/模式
    chooseMode: "游戏模式",
    chooseScene: "选择场景",
    chooseOpponent: "选择对手",
    AIVs: "AI对战",
    playersVs: "双人对战",
    onlinePlayer: "在线对战",
    setAlias: "设置玩家名",
    gamePlay: "游戏进行",
    onlineLobby: "在线大厅",
    addNewFriend: "添加新好友",

    // 模式描述
    aiModeDesc: "挑战我们的智能AI对手",
    playersModeDesc: "与朋友本地对战",
    onlineModeDesc: "与世界各地的玩家对战",
    tournamentModeDesc: "参加淘汰赛比赛",

    // 锦标赛
    tournament: "锦标赛",
    startTournament: "开始比赛",
    nbrPlayer: "玩家数量：",
    final: "决赛 !",
    waitNextRound: "等下一轮...",
    classement: "排行榜",
    leader: "领先者",
    points: "积分",
    type1v1: "1对1",
    typeTournament: "锦标赛",
    typeAI: "AI对战",
    match1v1: "1对1比赛",
    matchTournament: "锦标赛比赛",
    matchAI: "AI比赛",

    // 比赛/历史
    matchHistory: "比赛历史",
    matchHistoryLast: "最近10场比赛",
    currentMatch: "当前比赛",
    nextMatch: "下一场比赛",
    noMatchHistory: "没有比赛历史",
    noMatchFound: "没有找到比赛",
    matchDetails: "比赛详情",
    winner: "获胜者",
    player1: "玩家 1",
    player2: "玩家 2",
    tournamentNumber: "限制 4, 8, 16",

    // 游戏
    racketUseText: "使用这些按键来控制你的球拍",

    // 统计/其他
    score: "积分",
    rank: "排名",
    rate: "胜率",
    date: "日期",
    opponent: "对手",
    type: "类型",
    result: "结果",
    win: "赢了",
    loss: "输了",
    matches: "比赛",
    wins: "赢",
    losses: "输",

    // 好友信息
    recentMatches: "最近比赛",
    loading: "加载中...",
    failedToLoad: "加载好友信息失败",
    totalMatches: "比赛总数",
    winRate: "胜率",
    inviteToGame: "邀请好友玩游戏",
    online: "在线",
    offline: "离线",
  },
};

// Expose translations globally for other modules
(window as any).translations = translations;

// Centralized function to update all translations
function updateAllTranslations(languageCode: string): void {
    // Core language change
    changeLanguage(languageCode);
    
    // Update all UI components
    updateTournamentLang();
    updateModeContainerTranslations();
    updateMatchHistoryTranslation();
    showLeaderBoard();
    updateMatchBanner();
    showRacketControlsBeforeStart('none');
    updateManageRightDisplay();
    applyI18nPlaceholders(translations, languageCode);
    
    // Update dynamic components
    if ((window as any).userMenuManager && typeof (window as any).userMenuManager.updateLanguageTranslations === 'function') {
        (window as any).userMenuManager.updateLanguageTranslations();
    }
    
    if ((window as any).friendInfoManager && typeof (window as any).friendInfoManager.updateFriendInfoTranslations === 'function') {
        (window as any).friendInfoManager.updateFriendInfoTranslations();
    }
}

// Change language
function changeLanguage(languageCode: string): void {
    const elements = document.querySelectorAll<HTMLElement>('[data-i18n]');
    elements.forEach(el => {
        const key = el.dataset.i18n;
        if (!key) return;

        const translation = translations[languageCode as LanguageCode]?.[key];
        if (translation) {
            el.textContent = translation;
        }
    });

    // Store the selected language in localStorage
    localStorage.setItem("lang", languageCode);

    const body = document.body;
    // Remove all language-specific classes
    body.classList.remove('font-en', 'font-fr', 'font-zh');

    // Add the class for the selected language
    if (languageCode === 'fr') {
        body.classList.add('font-fr');
    } else if (languageCode === 'en') {
        body.classList.add('font-en');
    } else if (languageCode === 'zh') {
        body.classList.add('font-zh');
    }
}


// select handler
const selector = document.getElementById('langSelector') as HTMLSelectElement | null;
if (selector) {
    console.log("Change language...")
    selector.addEventListener('change', function (evt) {
        const target = evt.target as HTMLSelectElement;
        const selectedLang = target.value;

        // Change language and update all content
        updateAllTranslations(selectedLang);
        
        // Change font for the selector itself
        if (selectedLang === 'zh') {
            selector.style.fontFamily = 'hanchanbanyuanti-Regular, sans-serif';
        } else {
            selector.style.fontFamily = 'SourGummy-Regular, serif';
        }
    });

    
    // detect initial browser language and saved preference
    const savedLang = localStorage.getItem("lang");
    const browserLang = (navigator as any).userLanguage || navigator.language || 'en-EN';
    const options = Array.from(selector.options).map(opt => opt.value);
    
    // Debug logs    
    // Use saved language first, then browser language, then default to English
    let startLang = 'en';
    if (savedLang && options.includes(savedLang)) {
        startLang = savedLang;
    } else {
        startLang = options.find(val => browserLang.includes(val)) || 'en';
    }

    changeLanguage(startLang);
    
    // Force update after a small delay to ensure DOM is ready
    setTimeout(() => {
        updateAllTranslations(startLang);
    }, 100);

    // updating select with start value
    selector.selectedIndex = options.indexOf(startLang);
    
    // Apply font immediately based on selected language
    if (startLang === 'zh') {
        selector.style.fontFamily = 'hanchanbanyuanti-Regular, sans-serif';
    } else {
        selector.style.fontFamily = 'SourGummy-Regular, serif';
    }

    // fill "The selected language is:"
    const browserLangElem = document.getElementById('browserLang');
    if (browserLangElem)
        browserLangElem.innerText = browserLang;
    
    const startLangElem = document.getElementById('startLang');
    if (startLangElem)
        startLangElem.innerText = startLang;
    }

function updateTournamentLang() {
  const lang = (localStorage.getItem("lang") as LanguageCode) || 'en';
  const roundId = (window as any).currentRoundId;
  const translatedName = roundNames[lang][roundId];

  const titles = document.querySelectorAll(".tournament-round-title");
  titles.forEach(title => {
    const el = title as HTMLElement;
    const specificId = el.dataset.roundId;
    const idToUse = specificId || roundId;
    const translatedName = roundNames[lang][idToUse];
    if (translatedName) el.textContent = translatedName;
  });

  const matches = document.querySelectorAll(".tournament-match-name");
  const matchLabel = roundNames[lang]["match"];
  matches.forEach(match => {
    const index = (match as HTMLElement).dataset.matchIndex;
    if (index) {
      match.textContent = `${matchLabel} ${index}`;
    }
  });

  const playerAliasInputs = document.querySelectorAll("[data-i18n-placeholder='playerAlias']");
  const playerAliasInputsLAbel = roundNames[lang]["playerAlias"];

  playerAliasInputs.forEach(input => {
  const el = input as HTMLInputElement;
  const index = el.dataset.playerIndex;
  if (index) {
    el.placeholder = `${playerAliasInputsLAbel} ${index}`;
  }
  });

  applyI18nPlaceholders(translations, lang);
}

function getLang() {
  const lang = (localStorage.getItem("lang") as keyof typeof translations) || "en";
  return translations[lang];
}

// Function to update translations when language changes
function updateModeContainerTranslations() {
  initializeModeContainer();
  initializeSceneContainer();
}

function updateMatchHistoryTranslation() {
  updateMatchHistory();
  showReducedMatchTable();
}

function updateManageRightDisplay(): void {
    const middleGameStart = document.getElementById("middleGameStart");
    if (middleGameStart && middleGameStart.style.display === "flex") {
        manageRightDisplay("middleGameStart");
    }
    else {
        manageRightDisplay("right-menu");
    }
}

function applyI18nPlaceholders(translations: any, lang: string) {
  const inputs = document.querySelectorAll("[data-i18n-placeholder]");

  inputs.forEach((input) => {
    const key = input.getAttribute("data-i18n-placeholder");
    if (key && translations[lang] && translations[lang][key]) {
      input.setAttribute("placeholder", translations[lang][key]);
    }
  });
}
