declare function load_model(model: string): void;
declare function create_game(): void;
declare function run_babylon(): void;
declare function stop_babylon(): void;
declare function resetSignInPage(): void;


//--------------------------------------------------------------------------
declare var game : gameData;
declare var matches: Match[];

function    handle_friend_req_notif()
{
    if (!game.has_friend_req)
        return;

    show_friends_page();
}

function    host_create_game()
{
    if (game.invitation_init == null)
    {
        console.log("No invitation");
        return ;
    }

    game.left = game.alias;
    game.right = game.invitation_init.to;

    setPlayersDisplay(game.left, game.right);

    load_model("pixel.glb");
    host_game_remote();
    start_2player_game();
}

function    guest_join_game()
{
    if (game.invitation == null)
    {
        console.log("No invitation");
        return ;
    }

    game.left=game.invitation.from;
    game.right=game.alias;
    
    setPlayersDisplay(game.left, game.right);

    load_model("pixel.glb");
    join_game_remote();
    start_2player_game();
}

function invite_remote_player(fromplayer : string, toplayer: string)
{
    if (!game.msg_socket)
        return;
    var dataReturn = {
        evt: "invite_remote_init",
        from: fromplayer,
        to: toplayer,
    }
    game.invitation_init = dataReturn;
    let dataJson : string = JSON.stringify(dataReturn);
    if (game.msg_socket)
        game.msg_socket.send(dataJson);
    console.log("info [client]: Send invitation to", toplayer);
}

function invite_remote(event: MouseEvent)
{
    event.preventDefault();

    const invited_user = (document.getElementById("invited_user")! as HTMLInputElement).value;
    invite_remote_player(game.alias, invited_user);
}

function accept_invitation(event: MouseEvent)
{
    if (game.invitation == null)
        showCustomAlert("No invitation");
    event.preventDefault();
    if (!game.invitation)
        return ;
    const dataReturn = {
            evt: "invite_remote_accept",
            from: game.invitation.from,
            to: game.invitation.to,
        }
    const dataJson = JSON.stringify(dataReturn);
    if (game.msg_socket)
        game.msg_socket.send(dataJson);
    console.log("info [client]: Accept invitation from ", game.invitation.from);
}

function busy_invitation()
{
    if (!game.invitation)
    {
        return ;
    }
    const dataReturn = {
            evt: "invite_remote_busy",
            from: game.invitation.from,
            to: game.invitation.to,
        }
    const dataJson = JSON.stringify(dataReturn);
    if (game.msg_socket)
        game.msg_socket.send(dataJson);
    console.log("info [client]: Busy for invitation from ", game.invitation.from);
    game.invitation = null;
    game.invitation_init = null;
}

function refuse_invitation(event: MouseEvent)
{
    if (game.invitation == null)
        showCustomAlert("No invitation");
    event.preventDefault();
    if (!game.invitation || !game.msg_socket)
        return ;
    const dataReturn = {
            evt: "invite_remote_refuse",
            from: game.invitation.from,
            to: game.invitation.to,
        }
    const dataJson = JSON.stringify(dataReturn);
    if (game.msg_socket)
        game.msg_socket.send(dataJson);
    console.log("info [client]: Refuse invitation from ", game.invitation.from);
}

function    AI_game()
{
    game.left=game.alias;
    game.right="AI";
    game.AI = true;
    AI_start();
    document.getElementById("player1Name")!.innerHTML = game.left;
    document.getElementById("player2Name")!.innerHTML = game.right;
    create_game("vs AI");
    load_model("pixel.glb");
    start_2player_game();
    console.log("info [client]: Game started with AI.");
}

function abandon_2player()
{
    'use strict';
    document.getElementById("score")!.innerHTML = game.leftScore + ":" + game.rightScore;
    document.getElementById("result")!.innerHTML = "Ready";
    game.reset_after_game();
}

function set_user_alias_1vs1()
{
    const element : HTMLInputElement | null = document.getElementById("player1AliasInput") as HTMLInputElement;
    if (element)
    {
        element.value = game.alias;
        element.placeholder = game.alias;
    }
}

// Set player
function setPlayersDisplay(player1: string, player2: string, isRemote?:boolean): void {
    if (isRemote) {
        (document.getElementById("player1Avatar") as HTMLImageElement)!.src = 'api/avatar/' + player1;
        (document.getElementById("player2Avatar") as HTMLImageElement)!.src = 'api/avatar/' + player2;
        document.getElementById("player1Name")!.innerHTML = player1;
        document.getElementById("player2Name")!.innerHTML = player2;
    } else {
        if (player1 == game.alias) {
            (document.getElementById("player1Avatar") as HTMLImageElement)!.src = 'api/avatar/' + player1;
        } else {
            (document.getElementById("player1Avatar") as HTMLImageElement)!.src = 'api/avatar/default';
        }
        document.getElementById("player1Name")!.innerHTML = player1;
        
        if (player2 == game.alias) {
            (document.getElementById("player2Avatar") as HTMLImageElement)!.src = 'api/avatar/' + player2;
        } else if (player2 == "AI_Bot") {
            (document.getElementById("player2Avatar") as HTMLImageElement)!.src = 'api/avatar/AI_Bot';
        } else {
            (document.getElementById("player2Avatar") as HTMLImageElement)!.src = 'api/avatar/default';
        }
        document.getElementById("player2Name")!.innerHTML = player2;
    }
}

//--------------------------------------------------------------------------

function load_pixel_game(): void {
    load_model("pixel.glb");
    create_game();

    game.ballPosX = 0;
    game.ballPosY = 0;
    game.leftScore = 0;
    game.rightScore = 0;
    
    if (game.AI)
        AI_start();
    start_2player_game();
}

function load_arc_game(): void {
    load_model("arc.glb");
    create_game();

    game.ballPosX = 0;
    game.ballPosY = 0;
    game.leftScore = 0;
    game.rightScore = 0;
    
    if (game.AI)
        AI_start();
    start_2player_game();
}

function set_player_alias(event: Event): void {
    event.preventDefault();

    const form = event.target as HTMLFormElement;
    const formData = new FormData(form);

    const alias1 = game.alias;
    const alias2 = (formData.get("player2alias") as string)?.trim();

    if (!alias1 || !alias2) {
        showCustomAlert("Player alias cannot be empty.");
        return;
    }

    if (alias1 === alias2) {
        showCustomAlert("Player 2 cannot have the same alias.");
        return;
    }

    game.left = alias1;
    game.right = alias2;

    const player1 = document.getElementById("player1Name");
    const player2 = document.getElementById("player2Name");
    console.log("Player 1 alias:", game.left);
    console.log("Player 2 alias:", game.right);
    if (player1) {
        player1.innerHTML = game.left;
    }
    if (player2) {
        player2.innerHTML = game.right;
    }
    select_scene();
}

function select_scene_AI(): void {
    game.AI = true;
    game.right = "AI_Bot";

    navigate_to("middleSelScene");
}

function select_scene(): void {
    navigate_to("middleSelScene");
}

function start_2player_game(): void {
    navigate_to("middleGameStart");
    const buttons = document.getElementsByClassName("button4");
    for (let i = 0; i < buttons.length; i++) {
        const btn = buttons[i] as HTMLElement;
        btn.style.display = "flex";
    }
    game.in_game_page = true;
    run_babylon();
}

function confirm_to_main_page(): void {
    const t = getLang();

    if (game.game_on || game.game_created) {
        showCustomAlert(t.returnMainPageConfirm, [
            { 
                text: t.cancel, 
                onClick: () => {} 
            },
            { 
                text: t.yesReturn, 
                onClick: () => to_main_page() 
            }
        ]);
    } else {
        to_main_page();
    }
}

function to_main_page(): void {
    stop_game();
    navigate_to("middlePrepare");
}

function scene_to_main_page(): void {
    if (game.logged_in == false)
        return;
    if (game.game_on || game.game_created) {
        confirm_to_main_page();
        return;
    }
    if (game.AI)
        game.AI = false;
    stop_game();
    navigate_to("middlePrepare");
}

function confirm_to_log_out(): void {
    const t = getLang();

    if (game.game_on || game.game_created) {
        showCustomAlert(t.logOutConfirm, [
            { 
                text: t.cancel, 
                onClick: () => {} 
            },
            { 
                text: t.yesLogOut, 
                onClick: () => log_out() 
            }
        ]);
    } else {
        log_out();
    }
}

async function log_out(): Promise<void> {
    try {
        (document.getElementById("user-avatar")! as HTMLImageElement).src = "/api/avatar/default";
        
        const response = await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include'
        });

        if (!response.ok) {
        console.log('Logout failed:', await response.text());
        }
    } catch (err) {
        console.log('Logout error:', err);
    }

    navigate_to("login");
    game.logged_in = false;
    const buttons = document.getElementsByClassName("button4");
    for (let i = 0; i < buttons.length; i++) {
        const btn = buttons[i] as HTMLElement;
        btn.style.display = "none";
    }
    stop_babylon();
    stop_game();
    game.reset_logout();
}

function sign_in(): void {
    navigate_to("sign-in");
}

function return_from_sign_in(event: Event): void {
    event.preventDefault();
    navigate_to("login");
}

function return_to_login(event: Event): void {
    event.preventDefault();
    navigate_to("login");
}

// New functions for user menu pages
function show_account_page(): void {

    hide_user_menu();
    navigate_to("account");

    const avatarHTML = document.getElementById('Profile Avatar') as HTMLImageElement;

    if (avatarHTML)
    {
        const timestamp = Date.now();
        avatarHTML.src = `/api/avatar/${game.alias}?ts=${timestamp}`;
    }
    else
        showCustomAlert("There is a problem");
}

function show_friends_page(): void {
    hide_user_menu();
    navigate_to("friends");
    userMenuManager.insertFriendsList(game.friendList);
}

function hide_user_menu(): void {
    set_box_visible(false);
}

// Manage user menu visibility
function manageVisibilityLogin(viewId: string): void {
    const authPages = ['login', 'sign-in', 'login-fail', 'login-2fa'];
    const navButtonWrapper = document.querySelector('.nav-button-wrapper') as HTMLElement;
    const authContainer = document.getElementById('authentification-container');

    if (authPages.includes(viewId)) {
        // Hide navigation buttons on auth pages
        if (navButtonWrapper) {
            navButtonWrapper.style.display = 'none';
        }
        // Show authentication container
        if (authContainer) authContainer.style.display = 'flex';
        showAuthTitle(true);
    } else {
        // Show all navigation elements on other pages
        if (navButtonWrapper) {
            navButtonWrapper.style.display = 'flex';
        }
        // Hide authentication container
        if (authContainer) authContainer.style.display = 'none';
        showAuthTitle(false);
    }

    // Reset avatar when leaving sign-in page
    const currentSignInPage = document.getElementById('sign-in');
    if (currentSignInPage && currentSignInPage.style.display === 'flex' && viewId !== 'sign-in') {
        console.log("Leaving sign-in page, resetting avatar...");
        if (typeof resetSignInPage === 'function') {
            resetSignInPage();
        }
    }
}

// Manage right display based on current view
function manageRightDisplay(viewId: string): void {
    const rightSettings = document.getElementById("right-menu");
    const matchHistorySection = document.getElementById("match-history-section") as HTMLElement;
    const gamePlaySection = document.getElementById("game-play-section") as HTMLElement;
    const classementRows = document.getElementById("classement-rows") as HTMLElement;

    if (rightSettings) {
        rightSettings.style.display = "flex";
        
        if (viewId === "middleGameStart") {
            if (matchHistorySection) {
                matchHistorySection.style.display = "none";
            }
            if (gamePlaySection) {
                gamePlaySection.style.display = "flex";
            }
            if (classementRows) {
                classementRows.classList.remove("max-h-[18rem]");
                classementRows.classList.remove("h-full");
            }
        } else {
            if (matchHistorySection) {
                matchHistorySection.style.display = "flex";
            }
            if (gamePlaySection) {
                gamePlaySection.style.display = "none";
            }
            if (classementRows) {
                classementRows.classList.add("max-h-[18rem]");
                classementRows.classList.remove("h-full");
            }
        }
    }
}

function navigate_to(viewId: string, push: boolean = true): void {
    console.log("Navigating to:", viewId, "push =", push);
    
    // Add stop game when leaving game page
    const currentGamePage = document.getElementById('middleGameStart');
    if (currentGamePage && currentGamePage.style.display === 'flex' && viewId !== 'middleGameStart') {
        console.log("Leaving game page, stopping game...");
        stop_game_reset();
        game.in_game_page = false;
    }

    if (viewId === 'middleGameStart')
        game.in_game_page = true;
    
    manageVisibilityLogin(viewId);
    
    const views = document.querySelectorAll('.app');

    if (viewId === 'user-details') {
        // Show only user-details
        const userDetails = document.getElementById('user-details');
        if (userDetails) userDetails.style.display = 'flex';
        return;
    }
    
    views.forEach(view => {
        const el = view as HTMLElement;
        el.style.display = 'none';
    });
    
    if (viewId === 'middleSetAlias') {
        showAliasPopup();
        return;
    }
    
    if (viewId === 'vsOnlineView') {
        showOnlineLobbyPopup();
        return;
    }

    if (viewId === 'tournament-popup') {
        showTournamentPopup();
        return;
    }
    const target = document.getElementById(viewId);
    const gameSections = ["middlePrepare", "middleSelScene", "middleGameStart", 
        "user-details","player-alias-section", 
        "tournamentView", "left-menu-tournament", "match-history-container"];
        
        // const userMenuPages = ["account", "friends", "settings"];
        const userMenuPages = ["account", "friends"];

    if (gameSections.includes(viewId)) {
        const game = document.getElementById('game') as HTMLElement | null;
        const tournamentView = document.getElementById('tournamentView') as HTMLElement | null;
        if (game) game.style.display = 'flex';

        gameSections.forEach(id => {
            const el = document.getElementById(id) as HTMLElement | null;
            if (el) {
                el.style.display = 'none';
            }
        });

        if (target) {
            (target as HTMLElement).style.display = 'flex';

            const leftTournament = document.getElementById("left-menu-tournament");
            const miniFriendList = document.getElementById("left-friends");
            if (leftTournament) {
                if (viewId === "tournamentView" || (viewId === "middleGameStart" && isTournament !== "false")) {
                leftTournament.style.display = "flex";
                miniFriendList!.style.display = "none";
                } else {
                    miniFriendList!.style.display = "flex";
                    leftTournament.style.display = "none";
                }
            }
            manageRightDisplay(viewId);
        }
    } else if (userMenuPages.includes(viewId)) {
        // Handle user menu pages using UserMenuManager
        if (typeof userMenuManager !== 'undefined') {
            userMenuManager.showPage(viewId);
        } else {
            console.log('UserMenuManager not found. Make sure usermenu.js is loaded.');
        }
    } else {
        if (target) {
            (target as HTMLElement).style.display = 'flex';
        }
    }

    // Navigate to the target view
    if (push) {
        history.pushState({ viewId: viewId }, '', `#${viewId}`);
    }
}

// Popstate navigation
window.addEventListener('popstate', (event) => {
    const viewId = (event.state?.viewId as string) || location.hash?.substring(1) || 'login';
    const userMenuPages = ["account", "friends"];

    // Prevent navigation to middleGameStart via browser back/forward if no game is active
    if (viewId === 'middleGameStart' && !game.game_created) {
        console.log("Blocked navigation to game page via browser history: no game created");
        showCustomAlert("No game founded or game stopped, redirecting to main page.");
        history.replaceState({ viewId: 'middlePrepare' }, '', '#middlePrepare');
        navigate_to('middlePrepare', false);
        return;
    }
    
    if (document.getElementById(viewId) || userMenuPages.includes(viewId)) {
        navigate_to(viewId, false);
    }
});

// Initial load navigation
window.addEventListener('DOMContentLoaded', () => {
    const viewId = location.hash?.substring(1) || 'login';
    const userMenuPages = ["account", "friends"];
    
    // Prevent initial load to middleGameStart if no game is active
    if (viewId === 'middleGameStart' && !game.game_created) {
        console.log("Blocked initial navigation to game page: no game created");
        showCustomAlert("No game founded or game stopped, redirecting to main page.");
        history.replaceState({ viewId: 'middlePrepare' }, '', '#middlePrepare');
        navigate_to('middlePrepare', false);
        return;
    }
    
    if (document.getElementById(viewId) || userMenuPages.includes(viewId)) {
        navigate_to(viewId, false);
    }
});


let isVisible = false;

function updateMenuState() {
    if (game.game_on || game.game_created) {
        console.log("Menu disabled during game");
        return;
    }
    show_menu_list();
}

function show_menu_list() {
    const elementId = 'user-details';
    const element = document.getElementById(elementId);

    if (!element) return;

    if (is_box_visible()) {
        set_box_visible(false);
    } else {
        set_box_visible(true);
        navigate_to(elementId);
    }
}

function is_box_visible(): boolean {
    return isVisible;
}

function set_box_visible(visible: boolean) {
    const element = document.getElementById('user-details');
    if (!element) return;

    isVisible = visible;
    element.style.display = visible ? 'initial' : 'none';
}

document.addEventListener('click', function(event) {
    const userDetails = document.getElementById('user-details');
    const toggleBox = document.getElementById('user-box');

    if (!isVisible || !userDetails) {
        return;
    }

    const target = event.target as Node;

    // if the click is inside the user details or toggle box, do nothing
    if (userDetails.contains(target) || (toggleBox && toggleBox.contains(target))) {
        return;
    }
    // Else, hide the user details box
    set_box_visible(false);
});


// User Profile Card Management
interface UserProfileData {
    alias: string;
    score: number;
    rank: number;
    rate: number;
    avatar?: string;
    online?: boolean;
}

interface UserCardData {
    alias: string;
    score: number;
    rank: number;
    rate: number;
    wins: number;
    losses: number;
    total_matches: number;
}

async function updateUserProfileCard(user_card: UserCardData): Promise<void> {
    try {
        // Get user data from the game object or API
        const userAlias = game.alias || localStorage.getItem('currentUserAlias') || 'Guest';
        
        // Update profile card elements
        const aliasElement = document.getElementById('profile-card-alias');
        const scoreElement = document.getElementById('profile-card-score');
        const rankElement = document.getElementById('profile-card-rank');
        const rateElement = document.getElementById('profile-card-rate');
        const winElement = document.getElementById('profile-card-wins');
        const loseElement = document.getElementById('profile-card-losses');
        const matchElement = document.getElementById('profile-card-matches');
        const avatarElement = document.getElementById('profile-card-avatar') as HTMLImageElement;
        const statusIndicator = document.getElementById('profile-status-indicator');
        
        if (aliasElement) aliasElement.textContent = user_card.alias;
        if (scoreElement) scoreElement.textContent = user_card.score.toString();
        if (rankElement) rankElement.textContent = `#${user_card.rank === -1? "null" : user_card.rank.toString()}`;
        if (rateElement) rateElement.textContent = `${(user_card.rate * 100).toFixed(1)}%`;
        if (winElement) winElement.textContent = user_card.wins.toString();
        if (loseElement) loseElement.textContent = user_card.losses.toString();
        if (matchElement) matchElement.textContent = user_card.total_matches.toString();
        
        // Update avatar
        if (avatarElement) {
            const timestamp = Date.now();
            const avatarPath = `/api/avatar/${game.alias}?ts=${timestamp}`; //getUserAvatarPath(userAlias);
            avatarElement.src = avatarPath;
            avatarElement.onerror = () => {
                avatarElement.src = 'assets/img/default.png';
            };
        }
        
        // Update online status
        if (statusIndicator) {
            statusIndicator.className = "absolute -top-1 -right-1 w-4 h-4 bg-green-400 border-2 border-white rounded-full shadow-sm";
        }
        
    } catch (error) {
        console.log('Error updating user profile card:', error);
        // Set default values in case of error
        setDefaultProfileValues();
    }
}

async function getUserScore(alias: string): Promise<number> {
    try {
        // Try to get from leaderboard data first
        const leaderboardData = topClassement || [];
        const userEntry = leaderboardData.find(entry => entry.alias === alias);
        if (userEntry) {
            return parseInt(userEntry.score) || 0;
        }
        // Fallback to API or return 0
        return 0;
    } catch {
        return 0;
    }
}

async function getUserRank(alias: string): Promise<number> {
    try {
        // Sort leaderboard by score and find user's position
        const leaderboardData = topClassement || [];
        const sortedBoard = [...leaderboardData].sort((a, b) => parseInt(b.score) - parseInt(a.score));
        const userIndex = sortedBoard.findIndex(entry => entry.alias === alias);
        return userIndex >= 0 ? userIndex + 1 : 999;
    } catch {
        return 999;
    }
}

async function getUserWinRate(alias: string): Promise<number> {
    try {
        // Calculate win rate from matches
        const userMatches = matches || [];
        if (userMatches.length === 0) return 0;
        
        const wins = userMatches.filter(match => match.result === 'win').length;
        return Math.round((wins / userMatches.length) * 100);
    } catch {
        return 0;
    }
}

function getUserAvatarPath(alias: string): string {
    // First try to use the API endpoint like the main avatar
    if (alias && alias !== 'Guest') {
        return `/api/avatar/${alias}`;
    }
    
    // Fallback to local avatar mappings
    const avatarMappings: { [key: string]: string } = {
        'user': 'assets/img/1.png',
        'Bob': 'assets/img/2.png',
        'Abcdefghijklmnop': 'assets/img/3.png',
        'yfan': 'assets/img/4.png',
        'John': 'assets/img/6.png',
        'xiaxu': 'assets/img/7.png',
        'chrhu': 'assets/img/8.png',
        'Lucy': 'assets/img/9.png',
        'Peter': 'assets/img/10.png',
        'leochen': 'assets/img/player1.jpg',
        'sw': 'assets/img/player2.jpg'
    };
    
    return avatarMappings[alias] || 'assets/img/default.png';
}

function setDefaultProfileValues(): void {
    const aliasElement = document.getElementById('profile-card-alias');
    const scoreElement = document.getElementById('profile-card-score');
    const rankElement = document.getElementById('profile-card-rank');
    const rateElement = document.getElementById('profile-card-rate');
    
    if (aliasElement) aliasElement.textContent = 'Guest';
    if (scoreElement) scoreElement.textContent = '0';
    if (rankElement) rankElement.textContent = '#-';
    if (rateElement) rateElement.textContent = '-%';
}

function showRacketControlsBeforeStart(action: 'show' | 'hide' | 'none') {
    const t = getLang();
    const racketLetter = document.getElementById("racketLetter");
    if (!racketLetter) return;
    if (action === 'hide') {
        racketLetter.classList.add("hidden");
        racketLetter.innerHTML = "";
    } else if (action === 'show') {
        racketLetter.classList.remove("hidden");
        // Get player names from DOM
        const player1Name = document.getElementById("player1Name")?.textContent || "Player 1";
        const player2Name = document.getElementById("player2Name")?.textContent || "Player 2";
        racketLetter.innerHTML = `
            <div class="flex flex-row gap-8 justify-center items-center mb-2">
                <div class="flex flex-col items-center">
                    <span class="font-bold text-xl text-red-700">${player1Name}</span>
                    <div class="flex flex-row items-center bg-red-100 rounded-xl px-4 py-2 shadow border border-red-200 gap-4 mt-2">
                        <div class="flex flex-col items-center">
                            <i class="fa-solid fa-caret-up text-red-700 text-lg"></i>
                            <i class="fa-solid fa-caret-down text-red-700 text-lg"></i>
                        </div>
                        <div class="flex flex-col items-center">
                            <span class="font-mono text-lg text-red-700">W</span>
                            <span class="font-mono text-lg text-red-700">S</span>
                        </div>
                    </div>
                </div>
                <span class="text-2xl font-bold mx-4 text-black self-center mt-[30px]">VS</span>
                <div class="flex flex-col items-center">
                    <span class="font-bold text-xl text-blue-700">${player2Name}</span>
                    <div class="flex flex-row items-center bg-blue-100 rounded-xl px-4 py-2 shadow border border-blue-200 gap-4 mt-2">
                        <div class="flex flex-col items-center">
                            <span class="font-mono text-lg text-blue-700">I</span>
                            <span class="font-mono text-lg text-blue-700">K</span>
                        </div>
                        <div class="flex flex-col items-center">
                            <i class="fa-solid fa-caret-up text-blue-700 text-lg"></i>
                            <i class="fa-solid fa-caret-down text-blue-700 text-lg"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="mt-2 text-lg text-center text-black" data-il8n="racketUseText">${t.racketUseText}</div>
            `;
    }
}

// Update user profile card based on rank 
function userProfileCardRank() {
    const currentPlayerRank = topClassement.findIndex(player => player.alias === game.alias) + 1;

    const userCard = document.getElementById("user-profile-card");
    const badge = document.getElementById('rank-badge') as HTMLElement;

    if (!userCard || !badge) return;

    // Reset classes for user card
    userCard.classList.remove("user-profile-card-1", "user-profile-card-2", "user-profile-card-3", "user-profile-card-all");
    
    // Reset classes for badge
    badge.classList.remove('rank-decoration-1', 'rank-decoration-2', 'rank-decoration-3', 'rank-decoration-all');
    badge.textContent = currentPlayerRank.toString();
        
    if (currentPlayerRank === 1) {
        userCard.classList.add("user-profile-card-1");
        badge.classList.add("rank-decoration-1");
    } else if (currentPlayerRank === 2) {
        userCard.classList.add("user-profile-card-2");
        badge.classList.add("rank-decoration-2");
    } else if (currentPlayerRank === 3) {
        userCard.classList.add("user-profile-card-3");
        badge.classList.add("rank-decoration-3");
    } else {
        userCard.classList.add("user-profile-card-all");
        badge.classList.add("rank-decoration-all");
    }
}
