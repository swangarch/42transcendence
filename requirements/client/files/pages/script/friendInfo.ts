declare var game: gameData;
declare var topClassement: {alias: string; score: string;}[];

interface FriendDetailInfo {
    alias: string;
    score: number;
    rate: number;
    rank: number;
    wins: number;
    losses: number;
    total_matches: number
    online: boolean;
}

class FriendInfoManager {
    private tooltip: HTMLElement | null = null;
    private currentFriend: string | null = null;
    private hideTimeout: number | null = null;
    private showTimeout: number | null = null;

    constructor() {
        this.createTooltipElement();
        this.bindEvents();
    }

    private createTooltipElement(): void {
        this.tooltip = document.createElement('div');
        this.tooltip.id = 'friend-info-tooltip';
        this.tooltip.className = 'fixed z-[9999] bg-gradient-to-br from-slate-800 to-slate-700 border-2 border-slate-600 rounded-2xl p-5 shadow-2xl opacity-0 translate-y-3 transition-all duration-300 ease-out pointer-events-none min-w-80 max-w-96 backdrop-blur-md hidden';
        
        document.body.appendChild(this.tooltip);
    }

    private bindEvents(): void {
        // mouse enter tooltip cancel hide
        this.tooltip?.addEventListener('mouseenter', () => {
            if (this.hideTimeout) {
                clearTimeout(this.hideTimeout);
                this.hideTimeout = null;
            }
        });

        // mouse leave tooltip enable hide
        this.tooltip?.addEventListener('mouseleave', () => {
            this.hideTooltip();
        });
    }

    public showFriendInfo(friendAlias: string, event: MouseEvent): void {
        // remove timeout
        if (this.hideTimeout) {
            clearTimeout(this.hideTimeout);
            this.hideTimeout = null;
        }

        // no need to reload for same friend
        if (this.currentFriend === friendAlias && this.tooltip?.style.display === 'block') {
            return;
        }

        this.currentFriend = friendAlias;

        // add delay
        this.showTimeout = window.setTimeout(() => {
            this.loadAndShowFriendInfo(friendAlias, event);
        }, 300);
    }

    private showFriendMatchHistory(friendRecords: Match[] | null)
    {
        if (!friendRecords)
            return;

        const friendRecordElement = document.getElementById('friend-record');
        if (!friendRecordElement)
            return;

        let recordHtml = "";

        if (friendRecords.length !== 0)
            recordHtml += `
                <h2 class="text-white text-xm mb-2" data-i18n="recentMatches">
                    Recent Matches
                </h2>
            `;

        for (const record of friendRecords)
        {
            recordHtml += `<div class="bg-gray-800 text-white p-3 rounded-lg mb-2 flex justify-between items-center shadow-md">
                <span class="w-1/3 text-white text-[14px] text-left">${formatDate(record.date)}</span>
                <span class="w-1/3 text-white text-[14px] text-center">${record.opponent}</span>
                <span class="w-1/3 ${record.result === 'win' ? "text-green-500" : "text-red-500" } text-[14px] text-right" data-i18n="${record.result}">${record.result === 'win' ? 'Win' : 'Loss'}</span>
            </div>`;
        }
        
        friendRecordElement.innerHTML = recordHtml;
        
        // Apply translations to the newly added content
        setTimeout(() => {
            this.updateFriendInfoTranslations();
        }, 10);
    }

    private async loadAndShowFriendInfo(friendAlias: string, event: MouseEvent): Promise<void> {
        if (!this.tooltip) return;

        try {
            // show loading state
            this.showLoadingState(event);

            const friendInfo = await this.fetchFriendInfo(friendAlias);

            const friendRecord = await this.fetchFriendRecord(friendInfo);
            
            // update content
            this.updateTooltipContent(friendInfo);
            create_friend_chart(friendInfo.wins, friendInfo.losses);
            if (friendRecord)
                this.showFriendMatchHistory(friendRecord);
            
            // Apply translations after all content is loaded
            setTimeout(() => {
                this.updateFriendInfoTranslations();
            }, 10);
            
            // update position
            this.updateTooltipPosition(event);

        } catch (error) {
            console.log('Error loading friend info:', error);
            this.showErrorState();
        }
    }

    private showLoadingState(event: MouseEvent): void {
        if (!this.tooltip) return;

        this.tooltip.innerHTML = `
            <div class="text-center text-white">
                <div class="animate-spin inline-block w-8 h-8 border-4 border-white border-t-transparent rounded-full mb-4"></div>
                <p class="text-lg font-medium" data-i18n="loading">Loading...</p>
            </div>
        `;

        this.updateTooltipPosition(event);
        this.showTooltip();
        
        // Apply translations after content is set
        setTimeout(() => {
            this.updateFriendInfoTranslations();
        }, 10);
    }

    private showErrorState(): void {
        if (!this.tooltip) return;

        this.tooltip.innerHTML = `
            <div class="text-center text-red-400">
                <i class="fas fa-exclamation-triangle text-3xl mb-4"></i>
                <p class="text-lg font-medium" data-i18n="failedToLoad">Failed to load friend info</p>
            </div>
        `;
        
        // Apply translations after content is set
        setTimeout(() => {
            this.updateFriendInfoTranslations();
        }, 10);
    }

    private get_friend_online_state(alias : string) {
        try{
            for (const friend of game.friendList)
            {
                if (friend.alias === alias)
                    return friend.online;
            }
        }
        catch(e)
        {
            return false;
        }
        return false;
    }

    private async fetchFriendInfo(friendAlias: string): Promise<FriendDetailInfo> {
        try{
            const response = await fetch(`/api/record/statistic/${friendAlias}`);

            const resp = await response.json();

            if (response.status === 404)
            {
                return {
                    alias: friendAlias,
                    score: 0,
                    wins: 0,
                    losses: 0,
                    rate: 0,
                    total_matches: 0,
                    rank: -1,
                    online: false
                };
            }
            else if (!response.ok)
                throw new Error(resp?.info || "Failed to fetch friend data");

            resp.data.online = this.get_friend_online_state(resp.data.alias);

            return resp.data;
        }
        catch (e)
        {
            console.log("info [client]: Error", e);
            return {
                alias: friendAlias,
                score: 0,
                wins: 0,
                losses: 0,
                rate: 0,
                total_matches: 0,
                rank: -1,
                online: false
            };
        }
    }
        
    private flip_score(score: string)
    {
        const scoreTab = score.split(":");
        return scoreTab[1] + ":" + scoreTab[0];
    }

    private async fetchFriendRecord(friendInfo: FriendDetailInfo)
    {
        let friendRecord: Match[] = [];
        const uri = "/api/record/" + friendInfo.alias;
        try{
            const res = await fetch(uri, {
                method: "GET",
            })

            if (!res.ok)
            {
                throw(new Error("Error from record server!"))
            }
            const resp = await res.json();

            friendRecord.length = 0;

            for (let i = resp.length - 1; i > resp.length - 4 && i >= 0; i--)
            {
                let record : Match = {
                id: i,
                date: resp[i].timestamp,
                opponent: (friendInfo.alias === resp[i].alias1) ? resp[i].alias2 : resp[i].alias1,
                score: (friendInfo.alias === resp[i].alias1) ? resp[i].score : this.flip_score(resp[i].score),
                type: resp[i].type,
                result: (friendInfo.alias === resp[i].winner) ? "win" : "loss"
                }
                friendRecord.push(record);
            }
            return friendRecord
        }
        catch(e)
        {
            console.log("info [client]: Error:", e);
            return null;
        }
    }

    private updateTooltipContent(friendInfo: FriendDetailInfo): void {
        if (!this.tooltip) return;

        const statusIcon = friendInfo.online ? '🟢' : '⚫';
        const statusColor = friendInfo.online ? 'text-green-400' : 'text-gray-400';
        const statusTextColor = friendInfo.online ? 'text-green-400 text-sm' : 'text-gray-400 text-sm';

        this.tooltip.innerHTML = `
            <div class="friend-info-content">
                <!-- Header -->
                <div class="flex items-center justify-between mb-6">
                    <div class="flex items-center gap-4">
                        <img src="/api/avatar/${friendInfo.alias}" alt="${friendInfo.alias}" 
                            class="w-14 h-14 rounded-full object-cover border-2 border-slate-500 shadow-lg">
                        <div>
                            <h3 class="text-xl font-bold text-white mb-1">${friendInfo.alias}</h3>
                            <p class="${statusColor} text-sm font-medium flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full ${friendInfo.online ? 'bg-green-400 animate-pulse' : 'bg-gray-400'}"></span>
                                <span class="${statusTextColor}" data-i18n="${friendInfo.online ? 'online' : 'offline'}">${friendInfo.online ? 'Online' : 'Offline'}</span>
                            </p>
                        </div>
                    </div>
                    <button onclick="friendInfoManager.hideTooltip()" 
                            class="text-slate-400 hover:text-white transition-colors duration-200 p-2 hover:bg-slate-600/50 rounded-lg">
                        <i class="fas fa-times text-lg"></i>
                    </button>
                </div>

                <!-- Stats -->
                <div class="grid grid-cols-3 gap-3 mb-6">
                    <div class="text-center p-4 bg-slate-700/50 rounded-xl hover:bg-slate-700/70 transition-colors duration-200">
                        <div class="text-2xl font-bold text-blue-400 mb-1">${friendInfo.score}</div>
                        <div class="text-xs text-slate-400 uppercase tracking-wider font-medium" data-i18n="score">Score</div>
                    </div>
                    <div class="text-center p-4 bg-slate-700/50 rounded-xl hover:bg-slate-700/70 transition-colors duration-200">
                        <div class="text-2xl font-bold text-green-400 mb-1">${friendInfo.total_matches}</div>
                        <div class="text-xs text-slate-400 uppercase tracking-wider font-medium" data-i18n="totalMatches">Total Matches</div>
                    </div>
                    <div class="text-center p-4 bg-slate-700/50 rounded-xl hover:bg-slate-700/70 transition-colors duration-200">
                        <div class="text-2xl font-bold text-green-400 mb-1">${friendInfo.wins}</div>
                        <div class="text-xs text-slate-400 uppercase tracking-wider font-medium" data-i18n="wins">Wins</div>
                    </div>
                    <div class="text-center p-4 bg-slate-700/50 rounded-xl hover:bg-slate-700/70 transition-colors duration-200">
                        <div class="text-2xl font-bold text-green-400 mb-1">${friendInfo.losses}</div>
                        <div class="text-xs text-slate-400 uppercase tracking-wider font-medium" data-i18n="losses">Losses</div>
                    </div>
                    <div class="text-center p-4 bg-slate-700/50 rounded-xl hover:bg-slate-700/70 transition-colors duration-200">
                        <div class="text-2xl font-bold text-green-400 mb-1">${(friendInfo.rate * 100).toFixed(1)}%</div>
                        <div class="text-xs text-slate-400 uppercase tracking-wider font-medium" data-i18n="winRate">Win Rate</div>
                    </div>
                    <div class="text-center p-4 bg-slate-700/50 rounded-xl hover:bg-slate-700/70 transition-colors duration-200">
                        <div class="text-2xl font-bold text-yellow-400 mb-1">#${friendInfo.rank === -1 ? "Null" : friendInfo.rank}</div>
                        <div class="text-xs text-slate-400 uppercase tracking-wider font-medium" data-i18n="rank">Rank</div>
                    </div>
                </div>

                <div id="friend-Chart-Container" class="w-[35%] h-[35%] m-auto" style="display: none">
                    <canvas id="friend-Chart"></canvas><br>
                </div>

                <div id="friend-record"></div>

                <!-- Action Buttons -->
                <div class="flex justify-center">
                    <button onclick="friendInfoManager.inviteToGame('${friendInfo.alias}')" 
                            class="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-8 py-3 rounded-xl transition-all duration-300 font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 active:scale-95 flex items-center gap-2">
                        <i class="fas fa-gamepad"></i>
                        <p class="text-white" data-i18n="inviteToGame">Invite to Game</p>
                    </button>
                </div>
            </div>
        `;
    }

    
    private updateTooltipPosition(event: MouseEvent): void {
        if (!this.tooltip) return;
        
        const rect = this.tooltip.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        
        let left = event.clientX + 15;
        let top = event.clientY - rect.height / 2;
        
        // avoid out of right bound
        if (left + rect.width > viewportWidth - 20) {
            left = event.clientX - rect.width - 15;
        }
        
        // avoid upper lower bound
        if (top < 20) {
            top = 20;
        } else if (top + rect.height > viewportHeight - 20) {
            top = viewportHeight - rect.height - 20;
        }

        this.tooltip.style.left = `${left}px`;
        this.tooltip.style.top = `${top}px`;
    }

    private showTooltip(): void {
        if (!this.tooltip) return;

        this.tooltip.classList.remove('hidden');
        // redraw
        this.tooltip.offsetHeight;
        this.tooltip.classList.remove('opacity-0', 'translate-y-3', 'pointer-events-none');
        this.tooltip.classList.add('opacity-100', 'translate-y-0', 'pointer-events-auto');
    }
    
    public hideTooltip(): void {
        if (!this.tooltip) return;

        if (this.showTimeout) {
            clearTimeout(this.showTimeout);
            this.showTimeout = null;
        }
        
        this.hideTimeout = window.setTimeout(() => {
            if (this.tooltip) {
                this.tooltip.classList.add('opacity-0', 'translate-y-3', 'pointer-events-none');
                this.tooltip.classList.remove('opacity-100', 'translate-y-0', 'pointer-events-auto');
                
                setTimeout(() => {
                    if (this.tooltip) {
                        this.tooltip.classList.add('hidden');
                    }
                }, 300);
            }
            this.currentFriend = null;
        }, 100);
    }
    
    public inviteToGame(friendAlias: string): void {
        console.log(`Inviting ${friendAlias} to game`);
        
        invite_remote_player(game.alias, friendAlias);
        this.hideTooltip();
    }
    
    // clean up
    public destroy(): void {
        if (this.hideTimeout) {
            clearTimeout(this.hideTimeout);
        }
        if (this.showTimeout) {
            clearTimeout(this.showTimeout);
        }
        if (this.tooltip) {
            document.body.removeChild(this.tooltip);
            this.tooltip = null;
        }
    }
    
    // Method to update language translations in friend info tooltip
    private updateFriendInfoTranslations(): void {
        if (!this.tooltip) return;

        const lang = localStorage.getItem("lang") || 'en';
        const translations = (window as any).translations;

        if (!translations || !translations[lang]) return;

        // Update all elements with data-i18n attributes in the tooltip
        const elements = this.tooltip.querySelectorAll<HTMLElement>('[data-i18n]');
        
        elements.forEach(el => {
            const key = el.dataset.i18n;
            if (!key) return;

            if (translations[lang][key]) {
                el.textContent = translations[lang][key];
            }
        });

        console.log(`🔄 Updated ${elements.length} friend info translation elements`);
    }
}

const friendInfoManager = new FriendInfoManager();