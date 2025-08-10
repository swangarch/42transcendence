interface Window {
    google: any;
  }

function initializeLoginPages() {
  console.log('📢 Initializing login page...');
  const login = document.getElementById('login');

  if (login) {
    console.log('📢 Login container found, clearing and adding form');
    login.innerHTML = '';
    
    // Create login form
    const loginFormElement = document.createElement('div');
    loginFormElement.innerHTML = `
      <div class="auth-container">
        <div class="header-container w-[98%] mb-0">
            <i class="fa-solid fa-user-lock mr-2 text-sm"></i>
            <h2 data-i18n="needLogin">Please login</h2>
        </div>
        <div class="auth-section">
            <div class="auth-image-section">
                <img src="assets/img/main-img-crop.jpg" alt="Login illustration" class="auth-image" />
            </div>
            <div class="auth-form-section">
                <form method="POST" action="/api/auth" class="login-window space-y-6" id="login-window" onsubmit="auth_check(event)">
                    <div class="flex-1 space-y-4">
                        <div class="input-with-icon">
                            <input 
                              class="inputInfo w-full" 
                              id="username" 
                              type="text" 
                              name="username" 
                              placeholder="Enter your username" 
                              data-i18n-placeholder="username" required
                            />
                            <i class="fa-solid fa-at input-icon"></i>
                        </div>
                        <div class="input-with-icon">
                            <input class="inputInfo w-full" 
                            id="password" 
                            type="password" 
                            name="password" 
                            placeholder="Enter your password" 
                            data-i18n-placeholder="password" required
                            />
                            <i class="fa-solid fa-lock input-icon"></i>
                            <i class="fa-solid fa-eye eye-icon" id="password-eye"></i>
                        </div>
                    </div>
                    <div class="flex flex-col gap-3 pt-4 items-center">
                        <button class="button2 flex-1" type="submit" data-i18n="login">Login</button>
                        <button class="button2 flex-1" type="button" onclick="sign_in()" data-i18n="signUp">Sign up</button>

                        <div class="mt-[20px] h-[50px]">
                          <div id="g_id_onload"
                              data-client_id="${google_client_id}"
                              data-context="signin"
                              data-ux_mode="popup"
                              data-callback="handleCredentialResponse"
                              data-auto_prompt="false">
                          </div>

                          <div id="google-login-btn" class="g_id_signin"
                              data-type="standard"
                              data-shape="rectangular"
                              data-theme="outline"
                              data-text="sign_in_with"
                              data-size="large"
                              data-logo_alignment="left">
                          </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
      </div>
    `;
    
    const formElement = loginFormElement.firstElementChild;
    if (formElement) {
      login.appendChild(formElement);
      console.log('📢 Login form added successfully');
    
      addEyesIcon('password');
      
      setTimeout(() =>{
          if (window.google && window.google.accounts && window.google.accounts.id) {
          window.google.accounts.id.initialize({
            client_id: google_client_id,
            callback: handleCredentialResponse,
          });

          window.google.accounts.id.renderButton(
            document.getElementById("google-login-btn")!,
            {
              theme: "outline",
              size: "large",
              type: "standard",
              shape: "rectangular",
              text: "sign_in_with",
              logo_alignment: "left",
            }
          );

        } else {
          console.log("info [client]: Google login library not loaded yet.");
        }
      }, 10); 
    }
  } else {
    console.log('info [client]: Login container not found!');
  }
}

// Setup avatar preview
function setupAvatarPreview(formElement: Element) {
  // Add event listener for avatar preview
  const avatarInput = formElement.querySelector('#create_avatar') as HTMLInputElement;
  const avatarPreview = formElement.querySelector('#user-avatar-preview') as HTMLImageElement;
  const avatarContainer = formElement.querySelector('.avatar-container') as HTMLElement;
  
  if (avatarInput && avatarPreview && avatarContainer) {
    // Click on avatar container to open file selector
    avatarContainer.addEventListener('click', function() {
      avatarInput.click();
    });
    
    // Handle file selection
    avatarInput.addEventListener('change', function(e) {
      const target = e.target as HTMLInputElement;
      if (target.files && target.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
          if (e.target?.result) {
            avatarPreview.src = e.target.result as string;
          }
        };
        reader.readAsDataURL(target.files[0]);
      } else {
        // Reset to default image if no file selected
        avatarPreview.src = 'assets/img/default.png';
      }
    });

    // Upload avatar
  }
}

function initializeSignInPages() {
  const signIn = document.getElementById('sign-in');
  
  if (signIn) {
    signIn.innerHTML = '';
    
    // Create sign in form
    const signInFormElement = document.createElement('div');
    signInFormElement.innerHTML = `
    <div class="auth-container">
      <div class="header-container w-[98%]">
        <i class="fa-solid fa-user-plus mr-2 text-sm"></i>
        <h2 data-i18n="createAccount">Create Account</h2>
      </div>
    
      <form class="login-window space-y-6" id="create-user-window" onsubmit="create_user(event)">
      <div class="flex flex-col">
        <div class="auth-section">
          <div class="auth-image-section">
            <div class="flex flex-col items-center space-y-3">
              <div class="avatar-container">
                <img id="user-avatar-preview" src="assets/img/default.png" alt="" class="cursor-pointer hover:opacity-80 transition-opacity" title="Click to upload image" />
              </div>
              <div class="text-center">
                <p class="text-sm font-medium text-gray-700" data-i18n="profilePicture">Profile Picture</p>
                <p class="text-sm text-gray-500 italic" data-i18n="clickToUpload">Click on image to upload</p>
              </div>
            </div>
          </div>
          <div class="auth-form-section">
            <div class="space-y-4">
              <div class="input-with-icon">
                <input class="inputInfo w-full" id="create_username" type="text" name="username" placeholder="Enter your username" data-i18n-placeholder="username" required/>
                  <i class="fa-solid fa-at input-icon"></i>
              </div>
              <div class="input-with-icon">
                <input class="inputInfo w-full" id="create_password" type="password" name="password" placeholder="Create a password" data-i18n-placeholder="password" required/>
                <i class="fa-solid fa-lock input-icon"></i>
                <i class="fa-solid fa-eye eye-icon" id="password-eye"></i>
              </div>
              <div class="input-with-icon">
                <input class="inputInfo w-full" id="create_alias" type="text" name="alias" placeholder="Choose your alias" data-i18n-placeholder="alias" required/>
                <i class="fa-solid fa-user input-icon"></i>
              </div>
              <input type="file" id="create_avatar" name="create_avatar" accept="image/png" style="display: none;" aria-describedby="avatar-help"/>
            </div>
          </div>
        </div>
              
        <div class="flex gap-3 pb-6 justify-center">
          <button class="button2 flex-1" type="button" data-i18n="returnBtn" onclick="return_from_sign_in(event)">Return</button>
          <button class="button2 flex-1" type="submit" data-i18n="signUp">Sign up</button>
        </div>
        </form>
      </div>
    </div>
    `;
    
    const formElement = signInFormElement.firstElementChild;
    if (formElement) {
      signIn.appendChild(formElement);
      
      setupAvatarPreview(formElement);

      addEyesIcon('create_password');
    }
  }
}

function initializeLoginFailPages() {
  const loginFail = document.getElementById('login-fail');
  
  if (loginFail) {
    loginFail.innerHTML = '';
    
    // Create login fail form
    const loginFailFormElement = document.createElement('div');
    loginFailFormElement.innerHTML = `
      <div class="auth-container">
        <div class="header-container w-[98%] mb-0">
            <i class="fa-solid fa-exclamation-triangle mr-2 text-sm text-red-500"></i>
            <h2 class="text-red-600" data-i18n="loginFailed">Login Failed</h2>
        </div>
        <div class="auth-section">
            <div class="auth-image-section">
                <img src="assets/img/main-img-crop.jpg" alt="Login failed illustration" class="auth-image" />
            </div>
            <div class="auth-form-section">
                <form class="login-window space-y-6" id="login-fail-window" onsubmit="login_fail(event)">
                    <div class="flex-1 space-y-4">
                        <div class="text-center space-y-4">
                            <p class="text-lg font-medium text-red-600" data-i18n="loginFailedMsg">Login failed, please retry!</p>
                        </div>
                    </div>
                    <div class="flex flex-col gap-3 pt-4 items-center">
                        <button class="button2 flex-1" onclick="return_to_login(event)" data-i18n="retry">Retry</button>
                    </div>
                </form>
            </div>
        </div>
      </div>
    `;
    
    const formElement = loginFailFormElement.firstElementChild;
    if (formElement) {
      loginFail.appendChild(formElement);
    }
  }
}

document.addEventListener('DOMContentLoaded', function() {
  console.log('📢 AuthPages: DOM loaded, initializing auth pages...');
  initializeLoginPages();
  initialize2FAPages();
  initializeSignInPages();
  initializeLoginFailPages();
  console.log('📢 AuthPages: All auth pages initialized');
});


function showAuthTitle(show: boolean) {
  const authTitle = document.querySelector('.auth-title-container') as HTMLElement;
  if (authTitle) {
    if (show) {
      authTitle.style.display = 'flex';
    } else {
      authTitle.style.display = 'none';
    }
  }
}

// Cleanup function to reset the sign-in page
function resetSignInPage() {
  const avatarPreview = document.querySelector('#user-avatar-preview') as HTMLImageElement;
  const avatarInput = document.querySelector('#create_avatar') as HTMLInputElement;
  const usernameInput = document.querySelector('#create_username') as HTMLInputElement;
  const passwordInput = document.querySelector('#create_password') as HTMLInputElement;
  const aliasInput = document.querySelector('#create_alias') as HTMLInputElement;
  
  if (avatarPreview) {
    avatarPreview.src = 'assets/img/default.png';
  }
  
  // Clear the file input
  if (avatarInput) {
    avatarInput.value = ''; 
  }
  
  // Clear all form inputs
  if (usernameInput) {
    usernameInput.value = '';
  }
  
  if (passwordInput) {
    passwordInput.value = '';
  }
  
  if (aliasInput) {
    aliasInput.value = '';
  }
}

function initialize2FAPages() {
  console.log('📢 Initializing 2FA page...');
  const login2FA = document.getElementById('login-2fa');

  if (login2FA) {
    console.log('📢 2FA container found, clearing and adding form');
    login2FA.innerHTML = '';
    
    // Create 2FA form with same structure as login
    const twoFAFormElement = document.createElement('div');
    twoFAFormElement.innerHTML = `
      <div class="auth-container">
        <div class="header-container w-[98%] mb-0">
            <i class="fa-solid fa-shield-halved mr-2 text-sm"></i>
            <h2 data-i18n="twoFactorAuth">Two-Factor Authentication</h2>
        </div>
        <div class="auth-section">
            <div class="auth-image-section">
                <img src="assets/img/main-img-crop.jpg" alt="2FA illustration" class="auth-image" />
            </div>
            <div class="auth-form-section">
                <form class="login-window space-y-6" onsubmit="verify2FA(event)">
                    <div class="flex-1 space-y-4">
                        <div class="text-center mb-6">
                            <p class="text-lg font-medium text-gray-700" data-i18n="enter2FACode">Enter 6-digit code</p>
                            <p class="text-sm text-gray-500 mt-2" data-i18n="checkAuthApp">Check your authenticator app</p>
                        </div>
                        <div class="input-with-icon">
                            <input 
                                class="inputInfo" 
                                id="twofa-code" 
                                type="text" 
                                maxlength="6" 
                                required 
                                placeholder="123456" 
                                autocomplete="one-time-code"
                            />
                            <i class="fa-solid fa-key input-icon"></i>
                        </div>
                    </div>
                    <div class="flex flex-col gap-3 pt-4 items-center">
                        <button class="button2 flex-1" type="submit" data-i18n="verifyBtn">Verify</button>
                        <button class="button2 flex-1" type="button" onclick="navigate_to('login')" data-i18n="returnBtn">Return</button>
                    </div>
                </form>
            </div>
        </div>
      </div>
    `;
    
    const formElement = twoFAFormElement.firstElementChild;
    if (formElement) {
      login2FA.appendChild(formElement);
      console.log('📢 2FA form added successfully');
    }
  } else {
    console.log('❌ 2FA container not found!');
  }
}

// Function to add eye icon for password visibility 
function addEyesIcon(inputId: string): void {
  const passwordInput = document.getElementById(inputId) as HTMLInputElement | null;
  const eyeIcon = document.getElementById(`${inputId}-eye`) as HTMLElement | null;

  if (passwordInput && eyeIcon) {
    eyeIcon.addEventListener('click', function () {
      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        eyeIcon.className = 'fa-solid fa-eye-slash eye-icon';
      } else {
        passwordInput.type = 'password';
        eyeIcon.className = 'fa-solid fa-eye eye-icon';
      }
    });
  }
}
