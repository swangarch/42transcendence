async function apiFetch(url: string, method: string = 'GET', body?: any) {
    const options: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
    };
    if (body) {
        options.body = JSON.stringify(body);
    }
    const res = await fetch(url, options);
    const data = await res.json();
    if (!res.ok) {
        console.log('info [client]: API error response: ', data.info);
        throw new Error(data.info || 'API error');
    }
    return data;
}

document.addEventListener("DOMContentLoaded", () => {
    initUserInfo();
});

interface PageConfig {
    id: string;
    title: string;
    content: string;
}

interface Friend {
    alias: string;
    state: 'pending' | 'accepted';
    fromUser?: boolean;
    online?: boolean;
}


class UserMenuManager {
    private pages: Map<string, PageConfig> = new Map();

    constructor() {
        this.initializePages();
    }

    private initializePages(): void {
        // Account Page
        this.pages.set('account', {
            id: 'account',
            title: 'Account Settings',
            content: `
                <div class="style-container">
                    <div class="header-container w-[98%] mb-0">
                        <i class="fa-solid fa-cog mr-2 text-sm"></i>
                        <h2 data-i18n="accountSetting">Account Settings</h2>
                    </div>
                    
                    <form id="account-form" class="flex-1 space-y-6 w-full px-8">
                        <div class="flex flex-col py-[2rem] w-full">
                            <div class="flex flex-row items-center px-8 w-full">
                                <!-- Avatar -->
                                <div class="flex flex-1 flex-col items-center px-8">
                                    <img id="Profile Avatar" src="" alt="Profile Avatar" class="w-40 h-40 rounded-full object-cover mb-4">
                                    <div class="text-center">
                                        <h2 id="profile-username" class="text-xl font-semibold">Username</h2>
                                        <p id="profile-email" class="text-gray-400">user@example.com</p>
                                    </div>
                                </div>

                                <!-- Editable Fields -->
                                <div class="flex-1 space-y-4">
                                    <div class="input-with-icon">
                                        <input
                                            id="username-input"
                                            type="text"
                                            value="Username"
                                            class="inputInfo w-full"
                                        />
                                        <i class="fa-solid fa-user input-icon"></i>
                                    </div>

                                    <div class="input-with-icon">
                                        <input
                                            id="password-input"
                                            type="password"
                                            value="********"
                                            class="inputInfo w-full" />
                                        <i class="fa-solid fa-lock input-icon"></i>
                                    </div>
                                </div>

                                <!-- Two-Factor Authentication (2FA) -->
                                <div id="twofa-section" class="flex-1 px-4 ml-8 p-4 bg-sky-50 bg-opacity-50 rounded-3xl text-center">
                                    <h2 class="text-sm whitespace-nowrap" data-i18n="faAuth">Two-Factor Authentication (2FA)</h2>
                                    <p id="twofa-status-text" class="text-sm mb-4 whitespace-nowrap" data-i18n="loadingTwoFaStatus">Loading 2FA status...</p>

                                    <!-- Toggle Switch pour 2FA -->
                                    <div class="flex items-center justify-center gap-3 mb-4">
                                        <span class="text-sm font-medium text-gray-700" data-i18n="disabled">Disabled</span>
                                        <label class="relative inline-flex items-center cursor-pointer">
                                            <input id="twofa-toggle-input" type="checkbox" class="sr-only peer">
                                            <div class="relative w-14 h-7 bg-red-500 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-6 after:w-6 after:transition-all peer-checked:bg-green-500"></div>
                                        </label>
                                        <span class="text-sm font-medium text-gray-700" data-i18n="enabled">Enabled</span>
                                    </div>


                                </div>
                            </div>

                            <!-- Buttons -->
                            <div class="flex gap-6 pt-4 justify-center w-full">
                                <button type="button" class="modern-btn modern-btn-secondary flex-1" onclick="userMenuManager.goBackToGame()" >
                                    <i class="fa-solid fa-arrow-left"></i>
                                    <span data-i18n="backToGame">Back to Game</span>
                                </button>
                                <button type="button" class="modern-btn modern-btn-danger flex-1" onclick="userMenuManager.deleteUser()">
                                    <i class="fa-solid fa-trash"></i>
                                    <span data-i18n="deleteUser">Delete user</span>
                                </button>
                                <button type="submit" class="modern-btn modern-btn-primary flex-1">
                                    <i class="fa-solid fa-save"></i>
                                    <span data-i18n="saveChanges">Save Changes</span>
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            `
        });
        // Friends Page
        this.pages.set('friends', {
            id: 'friends',
            title: 'Friends',
            content: `
                <div class="style-container w-full max-w-[30rem] item-center">
                    <div class="header-container w-[98%] mb-0">
                        <i class="fa-solid fa-users mr-2 text-sm"></i>
                        <h2 data-i18n="friends">Friends</h2>
                    </div>
                    <div class="max-w-[400px] mx-auto text-center items-center">
                        <!-- Add New Friend -->
                        <div class="flex gap-4 my-8">
                            <input type="text" id="add-friend-input" class="inputInfo w-full pl-4" placeholder="Enter username to add" data-i18n-placeholder="enterUsername">
                            <button class="modern-btn modern-btn-primary whitespace-nowrap py-2" onclick="userMenuManager.addFriend()">
                                <i class="fa-solid fa-user-plus"></i>
                                <span data-i18n="addNewFriend">Add Friend</span>
                            </button>
                        </div>

                        <!-- Friends List -->
                        <div class="friends-list space-y-4">
                            <div id="friends-container" class="max-h-[600px] overflow-y-auto overflow-x-hidden scrollbar-custom"></div>
                        </div>

                        <button class="modern-btn modern-btn-secondary mb-4 mx-auto" onclick="userMenuManager.goBackToGame()" >
                            <i class="fa-solid fa-arrow-left"></i>
                            <span data-i18n="backToGame">Back to Game</span>
                        </button>
                    </div>
                </div>
            `
        });
    }

    public insertFriendsList(data: any[]) {
        const friendList = this.renderFriendsList(data);

        const friendHTML = document.getElementById('friends-container');
        if (!friendHTML)
            return;
        friendHTML.innerHTML = friendList;
    }

    public renderFriendsList(friends: any[]): string {
        return friends.map(friend => {
            try {
                const friendStr = encodeURIComponent(JSON.stringify(friend));
                
                if (friend.state === "pending" && !friend.fromUser)
                {
                    return `   
                        <div class="flex items-center justify-between bg-gray-300 p-3 rounded-full mb-2 gap-4">
                            <div class="w-10 h-10 rounded-full overflow-hidden flex-shrink-0">
                                <img src="/api/avatar/${friend.alias}" alt="${friend.alias}" class="w-full h-full object-cover"/>
                            </div>

                            <div class="flex items-center gap-4">
                                <span class="text-white font-medium text-xl">${friend.alias}</span>
                            </div>
                            
                            <div class="flex items-center gap-2">
                                <span class="text-white font-medium text-xl" data-i18n="friendPending">${friend.state}</span>
                            </div>
                            
                            <div class="flex items-center gap-1">
                                <button 
                                    class="modern-icon-btn modern-icon-danger"
                                    onclick="userMenuManager.deleteFriend(decodeURIComponent('${friendStr}'))"
                                    title="Reject request">
                                    <i class="fa-solid fa-xmark"></i>
                                </button>
                            </div>
                            
                            <div class="flex items-center gap-1">
                                <button 
                                    class="modern-icon-btn modern-icon-success"
                                    onclick="userMenuManager.acceptFriendRequest(decodeURIComponent('${friendStr}'))"
                                    title="Accept request">
                                    <i class="fa-solid fa-check"></i>
                                </button>
                            </div>
                        </div>
                    `
                }
                else if (friend.state === "pending" && friend.fromUser)
                {
                    return `   
                        <div class="flex items-center justify-between bg-gray-300 p-3 rounded-full mb-2 gap-4">
                            <div class="w-10 h-10 rounded-full overflow-hidden flex-shrink-0">
                                <img src="/api/avatar/${friend.alias}" alt="${friend.alias}" class="w-full h-full object-cover"/>
                            </div>
                            
                            <div class="flex items-center gap-4">
                                <span class="text-white font-medium text-xl">${friend.alias}</span>
                            </div>
                            
                            <div class="flex items-center gap-2">
                                <span class="text-white font-medium text-xl" data-i18n="friendPending">${friend.state}</span>
                            </div>
                            
                            <div class="flex items-center gap-1">
                                <button 
                                    class="modern-icon-btn modern-icon-danger"
                                    onclick="userMenuManager.deleteFriend(decodeURIComponent('${friendStr}'))"
                                    title="Cancel request">
                                    <i class="fa-solid fa-xmark"></i>
                                </button>
                            </div>
                        </div>
                    `
                }
                else if (friend.state === "accepted")
                {
                    return `   
                        <div class="flex items-center justify-between bg-gray-300 p-3 rounded-full mb-2 gap-4">
                            <div class="w-10 h-10 rounded-full overflow-hidden flex-shrink-0">
                                <img src="/api/avatar/${friend.alias}" alt="${friend.alias}" class="w-full h-full object-cover"/>
                            </div>
                            
                            <div class="flex items-center gap-4">
                                <span class="text-white font-medium text-xl">${friend.alias}</span>
                            </div>
                            
                            <div class="flex items-center gap-2">
                                <span class="text-white font-medium text-xl" data-i18n="friendAccepted">${friend.state}</span>
                            </div>
                            
                            <div class="flex items-center gap-1">
                                <button 
                                    class="modern-icon-btn modern-icon-danger"
                                    onclick="userMenuManager.deleteFriend(decodeURIComponent('${friendStr}'))"
                                    title="Remove friend">
                                    <i class="fa-solid fa-user-minus"></i>
                                </button>
                            </div>
                        </div>
                    `
                }
            }
            catch (e)
            {
                return "";
            }
        }).join('');
    }

    //input editable
    public toggleEdit(id: string): void {
        const input = document.getElementById(id) as HTMLInputElement;
        if (input) {
            input.readOnly = false;
            input.focus(); // focus to input
            input.setSelectionRange(input.value.length, input.value.length); //the end of input
        }
    }

    public async acceptFriendRequest(friend: string) {
        try
        {
            const friendObj = JSON.parse(friend);

            const body = {from: friendObj.alias, to:game.alias, accepted: true};
            const response = await fetch("/api/friends/accept", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(body),
                credentials: 'include',
            })
            const resp = await response.json();
            if (!response.ok) {
                throw new Error(JSON.stringify(resp) || 'Failed to create user');
            }
            console.log("info [client]: accept friend request.");
        }
        catch (e)
        {
            console.log("info [client]: Failed to accept friend request.");
        }
    }


    public async deleteFriend(friend: string) {
        try
        {
            const friendObj = JSON.parse(friend);

            const body = {from: friendObj.alias, to: game.alias};
            const response = await fetch("/api/friends/delete", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(body),
                credentials: 'include',
            })
            const resp = await response.json();
            if (!response.ok) {
                throw new Error(JSON.stringify(resp) || 'Failed to delete user');
            }
            console.log("info [client]: Delete friend request.");
        }
        catch (e)
        {
            console.log("info [client]: Failed to accept friend request.");
        }
    }

    
    public async addFriend(): Promise<void> {
        const input = document.getElementById('add-friend-input') as HTMLInputElement;
        if (!input || !input.value.trim()) return;
        
        const currentUserAlias = game.alias;
        const friendAlias = input.value.trim();
        
        try {
            const response = await fetch('/api/friends/add/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    from: currentUserAlias, 
                    to: friendAlias 
                }),
                credentials: 'include',
            });

            if (response.ok) {
                const result = await response.json();
                console.log(`Friend ${friendAlias} request send successfully!`);
                input.value = '';
            } else if (response.status === 401) {
                showCustomAlertStrict('Authentication required.');
            } else if (response.status === 404) {
                showCustomAlertStrict('User not exist.');
            } else if (response.status === 409) {
                showCustomAlertStrict('User already added.');
            } else if (response.status === 500) {
                showCustomAlertStrict('Server error.');
            } else {
                showCustomAlertStrict('Failed to add friend');
            }

        } catch (error) {
            console.log('Error adding friend:', error);
            showCustomAlertStrict('Error adding friend');
        }
    }

    // show page by page id
    public showPage(pageId: string): void {
        const page = this.pages.get(pageId);
        if (!page) {
            console.log(`Page ${pageId} not found`);
            return;
        }

        // Remove existing page if it exists
        const existingPage = document.getElementById(pageId);
        if (existingPage) {
            existingPage.remove();
        }

        // Create new page
        const pageElement = document.createElement('div');
        pageElement.className = 'app';
        pageElement.id = pageId;
        pageElement.style.display = 'flex';
        pageElement.innerHTML = page.content;

        // Add to body
        document.body.appendChild(pageElement);

        // Setup events for this page
        this.setupPageEvents(pageId);

        // Load existing data if needed 
        this.loadPageData(pageId);
        
        // Apply current language translations to the newly created page
        setTimeout(() => {
            this.updateLanguageTranslations();
        }, 50); // Small delay to ensure DOM is ready
    }

    //add event listener for page
    private setupPageEvents(pageId: string): void {
        switch (pageId) {
            case 'account':
                this.setupAccountEvents();
                break;
            case 'friends':
                this.setupFriendsEvents();
                break;
        }
    }

    // listen submit for account page
    private setupAccountEvents(): void {
        const accountForm = document.getElementById('account-form');
        if (accountForm) {
            accountForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveAccountSettings();
            });
        }
        
        // Toggle switch pour 2FA
        const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;

        twofaToggle?.addEventListener('change', (event) => {
            event.preventDefault();
            const isChecked = twofaToggle.checked;
            if (isChecked && !game.state2fa) {
                // Activate 2FA
                this.start2FASetup(game.username);
            } else if (!isChecked && game.state2fa) {
                // Deactivate 2FA
                this.disable2FA(game.username);
            }
        });
    }


    // listen submit for friend page
    private setupFriendsEvents(): void {
        const friendSearch = document.getElementById('friend-search') as HTMLInputElement;
        if (friendSearch) {
            friendSearch.addEventListener('keypress', (e) => { 
                if (e.key === 'Enter') {
                    this.searchFriends();
                }
            });
        }

        const addFriendInput = document.getElementById('add-friend-input') as HTMLInputElement;
        if (addFriendInput) {
            addFriendInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.addFriend();
                }
            });
        }
    }
    
    // load account data
    private loadPageData(pageId: string): void {
        switch (pageId) {
            case 'account':
                this.loadAccountData();
                break;
        }
    }
    
    private async loadAccountData(): Promise<void> {
        try
        {
            if (!game.logged_in) {
                await initUserInfo();
            }
            const userId = game.username;
            const response = await fetch(`/api/users/${userId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
            });
            
            if (response.ok) {
                const userData = await response.json();
                this.updateAccountUI(userData);
                this.update2FAUI();
            } else if (response.status === 401) {
                showCustomAlert('Please login first');
            } else if (response.status === 404) {
                showCustomAlert('User not exist.');
            } else if (response.status === 403) {
                showCustomAlert('Forbidden.');
            } else {
                showCustomAlert('Server error occurred');
            }
        } catch (error) {
            console.log('Error loading user data:', error);
        }
    }

    // Public interaction method
    public searchFriends(): void {
        const search = document.getElementById('friend-search') as HTMLInputElement;
        if (search && search.value.trim()) {
            console.log('Searching for friends:', search.value);
            showCustomAlert(`Searching for: ${search.value}`);
        }
    }

    public goBackToGame(): void {
        if (typeof navigate_to === 'function') {
            navigate_to('middlePrepare');
        }
    }
    private getAccountFormData(): any {
        const aliasInput = document.getElementById('username-input') as HTMLInputElement;
        const passwordInput = document.getElementById('password-input') as HTMLInputElement;
        
        const formData: any = {};
        
        if (aliasInput && aliasInput.value) {
            formData.alias = aliasInput.value;
        }
        
        if (passwordInput && passwordInput.value && passwordInput.value !== '********') {
            formData.password = passwordInput.value;
        }
        
        return formData;
    }

    public async saveAccountSettings(): Promise<void> {
        const formData = this.getAccountFormData();
        const userId = game.username;
        
        try {
            const response = await fetch(`/api/users/${userId}`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData),
                credentials: 'include',
            });
            
            const result = await response.json();            
            if (response.ok) {
                showCustomAlert('user modified.');
                console.log(result.info);
                const Element_username = document.getElementById('user-name');
                game.alias = formData.alias;
                if (Element_username) 
                    Element_username.innerHTML = formData.alias;

                const usernameElement = document.getElementById('profile-username');
                const emailElement = document.getElementById('profile-email');

                if (usernameElement) usernameElement.textContent = game.alias;
                if (emailElement) emailElement.textContent = game.username;

            } else if (response.status === 401) {
                showCustomAlert(result.info || 'Unauthorized.');
            } else if (response.status === 404) {
                showCustomAlert(result.info || 'User info not found.');
            } else if (response.status === 409) {
                showCustomAlert(result.info || 'User info not modified.');
            } else if (response.status === 400) {
                showCustomAlert(result.info || 'Failed to modify.');
            } else {
                showCustomAlert(result.info || 'Failed to save account settings');
            }
        } catch (error) {
            console.log('Error saving account settings:', error);
            showCustomAlert('Error saving account settings');
        }
    }

    public deleteUser(): void {
        const alertStr : string = "Are you sure to delete your account?";  

        showCustomAlert(alertStr, [
            { text: "Confirm",
                onClick: () => { this.confirmDeleteUser();}
            },
            { text: "Cancel", 
                onClick: () => { console.log("info [client]: Cancel delete account."); } 
            }
        ]);
    }


    private async confirmDeleteUser(): Promise<void> {
        try {
            if (!game.username)
                return;

            const email = encodeURIComponent(game.username)
            const response = await fetch(`/api/users/${email}`, {
                method: 'Delete',
                credentials: 'include',
            });
            
            const result = await response.json();
            if (response.status === 200)
            {
                showCustomAlert('user deleted.');
                
                setTimeout(() => {
                    log_out();
                    navigate_to('login');
                }, 1000);
            }
            else if (response.status === 401 || response.status === 400 || response.status === 404 || response.status === 409) {
                showCustomAlert(result.info);
            } else {
                showCustomAlert(result.info)
            }
        } catch (error) {
            console.log('Error deleting user:', error);
            showCustomAlert('Error deleting user: ' + error);
        }
    }

    private updateAccountUI(userData: any): void {
        const usernameElement = document.getElementById('profile-username');
        const emailElement = document.getElementById('profile-email');
        const usernameInput = document.getElementById('username-input') as HTMLInputElement;
        const emailInput = document.getElementById('email-input') as HTMLInputElement;
        
        if (usernameElement) usernameElement.textContent = userData.alias;
        if (usernameInput) usernameInput.value = userData.alias;
        if (emailElement) emailElement.textContent = game.username;
        if (emailInput) emailInput.value = game.username;
    }

    public async loadMiniFriendsList(friends: Friend[]): Promise<void> {
        const userId = game.alias;

        if (!userId) {
            return;
        }   
        try {
            
            const container = document.getElementById('mini-friends-container');
            if (!container) return;

            const sortedFriends = friends.filter((friend: Friend) => friend.state === "accepted")
                .sort((a: Friend, b: Friend) => {
                    return Number(b.online) - Number(a.online);
                });

            container.innerHTML = sortedFriends
            .filter((friend: Friend) => friend.state === 'accepted')
            .map((friend: Friend) => {
                const statusColor = friend.online ? 'text-green-400' : 'text-gray-400';
                const statusTextColor = friend.online ? 'text-green-400 text-sm' : 'text-gray-400 text-sm';
                const avatarUrl = '/api/avatar/' + friend.alias;
                return `
                    <div class="flex justify-between items-center bg-gray-400/20 hover:bg-gray-600/30 transition-all px-4 py-1 rounded-xl w-full shadow-sm friend-item h-12" 
                        data-friend-alias="${friend.alias}"
                        onmouseenter="friendInfoManager.showFriendInfo('${friend.alias}', event)"
                        onmouseleave="friendInfoManager.hideTooltip()">
                        
                        <div class="w-10 h-10 rounded-full overflow-hidden flex-shrink-0">
                            <img src="${avatarUrl}" alt="${friend.alias}" class="w-full h-full object-cover"/>
                        </div>
                        <span class="text-white text-lg font-semibold">${friend.alias}</span>
                        <span class="${statusColor} text-base ml-2">
                            ${friend.online ? '🟢' : '⚫'} 
                            <span class="${statusTextColor}" data-i18n="${friend.online ? 'online' : 'offline'}">${friend.online ? 'Online' : 'Offline'}</span>
                        </span>
                    </div>
                `;
            }).join('');

            // Apply translations to the newly created content
            setTimeout(() => {
                this.updateTranslationsInContainer(container, 'mini-friends-list');
            }, 10);

        } catch (error) {
            console.log('Error loading mini friends list:', error);
        }
    }

    private twoFAQrUrl: string = '';

    private update2FAUI() {
        const statusText = document.getElementById('twofa-status-text');
        const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;

        if (!statusText || !twofaToggle) return;

        if (game.state2fa) {
            statusText.textContent = '2FA is ENABLED.';
            twofaToggle.checked = true;
        } else {
            statusText.textContent = '2FA is DISABLED.';
            twofaToggle.checked = false;
        }
    }

    public async start2FASetup(username: string): Promise<void> {
        try {
            console.log(username);
            const data = await apiFetch(`/api/2fa/setup/${encodeURIComponent(username)}`, 'GET');
            this.twoFAQrUrl = data.qrImageUrl;

            // Show 2FA setup popup
            this.show2FASetupPopup(
                // Callback for verification
                async (tokenInput: string) => {
                    if (!tokenInput) {
                        // Switch back to its previous state
                        const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;
                        if (twofaToggle) twofaToggle.checked = game.state2fa;
                        return showCustomAlertStrict('2FA setup cancelled.');
                    }

                    try {
                        const data = await apiFetch(`/api/2fa/setup/${encodeURIComponent(username)}`, 'PATCH', { token: tokenInput });
                        if (data.success) {
                            game.state2fa = true;
                            this.update2FAUI();
                            showCustomAlertStrict('2FA enabled successfully!');
                        } else {
                            // Switch back to its previous state
                            const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;
                            if (twofaToggle) twofaToggle.checked = game.state2fa;
                            showCustomAlertStrict(data.info || 'Invalid code, please try again.');
                        }
                    } catch (e: any) {
                        // Switch back to its previous state
                        const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;
                        if (twofaToggle) twofaToggle.checked = game.state2fa;
                        showCustomAlertStrict(e.message || 'Verification failed.');
                    }
                },
                () => {
                    // Cancel callback
                    const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;
                    if (twofaToggle) twofaToggle.checked = game.state2fa;
                    showCustomAlertStrict('2FA setup cancelled.');
                }
            );
        } catch (e: any) {
            showCustomAlertStrict(`Failed to setup 2FA: ${e.message}`);
            // Switch back to its previous state
            const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;
            if (twofaToggle) {
                twofaToggle.checked = game.state2fa;
            }
        }
    }



    public async disable2FA(username: string): Promise<void> {
        const twofaToggle = document.getElementById('twofa-toggle-input') as HTMLInputElement;
        
        // Show custom popup instead of prompt
        this.showTwoFAInputPopup(
            // Callback for confirmation
            async (tokenInput: string) => {
                if (!tokenInput) {
                    // Switch back to its previous state
                    if (twofaToggle) twofaToggle.checked = game.state2fa;
                    return showCustomAlertStrict('2FA disable cancelled.');
                }

                try {
                    const data = await apiFetch(`/api/2fa/setup/${encodeURIComponent(username)}`, 'DELETE', { token: tokenInput });
                    if (data.success) {
                        game.state2fa = false;
                        this.update2FAUI();
                        showCustomAlertStrict('2FA has been disabled.');
                    } else {
                        // Switch back to its previous state
                        if (twofaToggle) twofaToggle.checked = game.state2fa;
                        showCustomAlertStrict(data.info || 'Failed to disable 2FA.');
                    }
                } catch (e: any) {
                    // Switch back to its previous state
                    if (twofaToggle) twofaToggle.checked = game.state2fa;
                    showCustomAlertStrict(e.message || 'Failed to disable 2FA.');
                }
            },
            () => {
                // Cancel callback
                if (twofaToggle) twofaToggle.checked = game.state2fa;
                showCustomAlertStrict('2FA disable cancelled.');
            }
        );
    }

    private show2FASetupPopup(
        onConfirm: (code: string) => void,
        onCancel: () => void
    ): void {
        // Create popup HTML
        const popupHTML = `
            <div id="twofa-setup-popup" class="fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black/50 z-50">
                <div class="bg-white p-6 rounded-xl shadow-lg max-w-xl w-[600px] text-center">
                    <h2 class="text-xl mb-4 text-gray-800">
                        <i class="fa-solid fa-shield-halved mr-2 text-blue-600"></i>
                        <span data-i18n="setup2FA">Setup 2FA</span>
                    </h2>
                    <p class="text-gray-600 mb-4" data-i18n="scanQRCode">Scan this QR code with your authenticator app:</p>
                    
                    <img id="twofa-setup-qr" src="${this.twoFAQrUrl}" alt="2FA QR Code" class="mb-4 mx-auto border-2 border-dashed p-2 border-gray-300 rounded-lg" />
                    
                    <p class="text-gray-600 mb-4" data-i18n="enterSetupCode">Then enter the 6-digit code:</p>
                    <input 
                        type="text" 
                        id="twofa-setup-field" 
                        placeholder="000000"
                        class="w-full px-3 py-2 border border-gray-300 rounded-xl text-center text-lg mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        maxlength="6"
                        autocomplete="off" />
                    
                    <div id="twofa-setup-message" class="text-sm mb-4"></div>
                    
                    <div class="flex gap-3 justify-center">
                        <button id="twofa-setup-cancel-btn" class="px-6 py-2 bg-gray-500 text-white rounded-xl hover:bg-gray-600 transition-colors">
                            <i class="fa-solid fa-xmark mr-2"></i>
                            <span class="text-white text-md" data-i18n="cancelBtn">Cancel</span>
                        </button>
                        <button id="twofa-setup-verify-btn" class="px-6 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors">
                            <i class="fa-solid fa-check mr-2"></i>
                            <span class="text-white text-md" data-i18n="verifyBtn">Verify</span>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add popup to page
        document.body.insertAdjacentHTML('beforeend', popupHTML);

        // Apply current language translations to the popup
        setTimeout(() => {
            this.updatePopupTranslations('twofa-setup-popup');
        }, 10);

        // Get elements
        const popup = document.getElementById('twofa-setup-popup');
        const input = document.getElementById('twofa-setup-field') as HTMLInputElement;
        const confirmBtn = document.getElementById('twofa-setup-verify-btn') as HTMLButtonElement;
        const cancelBtn = document.getElementById('twofa-setup-cancel-btn') as HTMLButtonElement;
        const message = document.getElementById('twofa-setup-message') as HTMLElement;

        // Only allow numbers
        input?.addEventListener('input', (e) => {
            const target = e.target as HTMLInputElement;
            target.value = target.value.replace(/\D/g, '');
        });

        // Function to handle confirmation
        const handle2FASetupConfirm = () => {
            const code = input?.value || '';
            if (code.length !== 6 || !/^\d{6}$/.test(code)) {
                if (message) {
                    message.textContent = 'Please enter a valid 6-digit code.';
                    message.style.color = 'red';
                }
                return;
            }
            close2FASetupPopup();
            onConfirm(code);
        };
        
        // Confirm button click and Enter key
        confirmBtn?.addEventListener('click', handle2FASetupConfirm);
        input?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handle2FASetupConfirm();
            }
        });
        
        // Close popup function
        const close2FASetupPopup = () => {
            popup?.remove();
        };

        // Cancel button and Escape key
        cancelBtn?.addEventListener('click', () => {
            close2FASetupPopup();
            onCancel();
        });
    }

    private showTwoFAInputPopup(
        onConfirm: (code: string) => void,
        onCancel: () => void
    ): void {
        // Create popup HTML
        const popupHTML = `
            <div id="twofa-input-popup" class="fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black/50 z-50">
                <div class="bg-white p-6 rounded-xl shadow-lg max-w-md w-[400px] text-center">
                    <h2 class="text-xl mb-4 text-gray-800" data-i18n="disable2FA">
                        <i class="fa-solid fa-shield-halved mr-2 text-blue-600"></i>
                        <span data-i18n="disable2FA">Disable 2FA</span>
                    </h2>
                    <p class="text-gray-600 mb-6" data-i18n="twofaInputPrompt">Please enter your 6-digit 2FA code to disable 2FA:</p>
                    <input 
                        type="text" 
                        id="twofa-input-field" 
                        placeholder="000000"
                        class="w-full px-3 py-2 border border-gray-300 rounded-xl text-center text-lg mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        maxlength="6"
                        autocomplete="off" />
                    <div class="flex gap-3 justify-center">
                        <button id="twofa-cancel-btn" class="px-6 py-2 bg-gray-500 text-white rounded-xl hover:bg-gray-600 transition-colors">
                            <i class="fa-solid fa-xmark mr-2"></i>
                            <span class="text-white text-md" data-i18n="cancelBtn">Cancel</span>
                        </button>
                        <button id="twofa-confirm-btn" class="px-6 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors">
                            <i class="fa-solid fa-check mr-2"></i>
                            <span class="text-white text-md" data-i18n="confirmBtn">Confirm</span>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add popup to page
        document.body.insertAdjacentHTML('beforeend', popupHTML);

        // Apply current language translations to the popup
        setTimeout(() => {
            this.updatePopupTranslations('twofa-input-popup');
        }, 10);

        // Get elements
        const popup = document.getElementById('twofa-input-popup');
        const input = document.getElementById('twofa-input-field') as HTMLInputElement;
        const confirmBtn = document.getElementById('twofa-confirm-btn') as HTMLButtonElement;
        const cancelBtn = document.getElementById('twofa-cancel-btn') as HTMLButtonElement;

        // Only allow numbers
        input?.addEventListener('input', (e) => {
            const target = e.target as HTMLInputElement;
            target.value = target.value.replace(/\D/g, '');
        });

        // Function to handle confirmation
        const handle2FAConfirm = () => {
            const code = input?.value || '';
            close2FAPopup();
            onConfirm(code);
        };
        
        // Confirm button click and Enter key
        confirmBtn?.addEventListener('click', handle2FAConfirm);
        input?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handle2FAConfirm();
            }
        });
        
        // Close popup function
        const close2FAPopup = () => {
            popup?.remove();
        };

        // Cancel button and Escape key
        cancelBtn?.addEventListener('click', () => {
            close2FAPopup();
            onCancel();
        });
    }

    // Method to update language translations in UserMenu pages
    public updateLanguageTranslations(): void {
        console.log('🔄 Updating UserMenu language translations...');
        
        // Update all UserMenu pages
        const userMenuPages = ['account', 'friends'];
        let totalElements = 0;
        
        userMenuPages.forEach(pageId => {
            const pageContainer = document.getElementById(pageId);
            if (pageContainer) {
                totalElements += this.updateTranslationsInContainer(pageContainer, `page: ${pageId}`);
            }
        });

        // Update mini friends list if visible
        const miniFriendsContainer = document.getElementById('mini-friends-container');
        if (miniFriendsContainer) {
            totalElements += this.updateTranslationsInContainer(miniFriendsContainer, 'mini-friends-list');
        }

        // Update any open popups
        const popupIds = ['twofa-setup-popup', 'twofa-input-popup'];
        popupIds.forEach(popupId => {
            const popup = document.getElementById(popupId);
            if (popup) {
                this.updateTranslationsInContainer(popup, `popup: ${popupId}`);
            }
        });
    }

    // Utility method to update translations in any container (page or popup)
    private updateTranslationsInContainer(container: HTMLElement, context: string = 'container'): number {
        const lang = localStorage.getItem("lang") || 'en';
        const translations = (window as any).translations;
        let elementsProcessed = 0;

        if (!translations || !translations[lang]) return 0;

        // Update all elements with data-i18n attributes
        const elements = container.querySelectorAll<HTMLElement>('[data-i18n]');
        
        elements.forEach(el => {
            const key = el.dataset.i18n;
            if (!key) return;

            if (translations[lang][key]) {
                const oldText = el.textContent;
                el.textContent = translations[lang][key];
                elementsProcessed++;
            }
        });

        // Update placeholders with data-i18n-placeholder attributes
        const placeholderElements = container.querySelectorAll<HTMLInputElement>('[data-i18n-placeholder]');
        placeholderElements.forEach(input => {
            const key = input.getAttribute('data-i18n-placeholder');
            if (!key) return;

            if (translations[lang][key]) {
                const oldPlaceholder = input.placeholder;
                input.placeholder = translations[lang][key];
                elementsProcessed++;
            }
        });

        return elementsProcessed;
    }

    // Simplified method to update popup translations (now uses the utility)
    private updatePopupTranslations(popupId: string): void {
        console.log(`🔄 Updating popup translations for: ${popupId}`);
        
        const popup = document.getElementById(popupId);
        if (!popup) return;

        const elementsProcessed = this.updateTranslationsInContainer(popup, `popup: ${popupId}`);
    }

}

const userMenuManager = new UserMenuManager();

if (typeof window !== 'undefined') {
    (window as any).userMenuManager = userMenuManager;
}

async function initUserInfo() {
    try {
        const data = await apiFetch(`/api/me`, 'GET');
        game.username = data.username;
        game.alias = data.alias;
        game.state2fa = data.twofa_enabled;
        
        if ((window as any).userMenuManager) {
            (window as any).userMenuManager.update2FAUI();
        }
        const user_name = document.getElementById('user-name');
        if (user_name) {
            user_name.innerText = game.alias;
        }
        
        const user_avatar = document.getElementById('user-avatar') as HTMLImageElement;
        if (user_avatar) {
            const timestamp = Date.now();
            user_avatar.src = `/api/avatar/${game.alias}?ts=${timestamp}`;
        }
        init_msg_socket();
        game.logged_in = true;
        navigate_to("middlePrepare")
    } catch (e: any) {
        console.log("Not logged in or token expired");
        navigate_to("login");
    }
}
