async function create_user(event: MouseEvent) {
  event.preventDefault(); 

  try {
    const username = (document.getElementById('create_username') as HTMLInputElement)?.value || "";
    const password = (document.getElementById('create_password') as HTMLInputElement)?.value || "";
    const alias = (document.getElementById('create_alias') as HTMLInputElement)?.value || "";

    const body = {username: username, password: password, alias: alias};

    const formData = new FormData();

    formData.append("userdata", JSON.stringify(body));

    const fileInput = document.getElementById('create_avatar') as HTMLInputElement | null;
    const file = fileInput?.files?.[0];

    if (file)
      formData.append('avatar', file);

    const response = await fetch('/api/users/', {
      method: 'POST',
      body: formData,
    })
    if (response.status === 413) {
        showCustomAlert("Too large.");
        return;
    }
    const resp = await response.json(); 
    if (response.status === 400 || response.status === 409) {
      showCustomAlert(resp?.info || 'Invalid input.');
      return;
    }
    if (!response.ok) {
      throw new Error(JSON.stringify(resp) || 'Failed to create user');
    }
    console.log('info [client]: User created successfully!');
    showCustomAlert('User created successfully!');
    setTimeout(() => {
        navigate_to("login");
    }, 1000);
  } catch (error) {
    console.log('info [client]: Error occured when creating user.');
    showCustomAlert('Error occured when creating user');
  }
}

async function get_alias(username: string) {
    const uri = "/api/users/" + username;
    try {
        const res = await fetch(uri, { method: "GET", credentials: 'include' });

        if (!res.ok) throw new Error("Error: wrong response from server!");

        const data = await res.json();
        game.alias = data.alias;
        game.username = username;

        document.getElementById('user-name')!.innerHTML = game.alias;
        game.left = game.alias;

        const timestamp = Date.now();
        (document.getElementById('user-avatar')! as HTMLImageElement).src = `/api/avatar/${game.alias}?ts=${timestamp}`;

    } catch (err) {
        console.log("info [client] Error: login failed:", err);
        navigate_to("login-fail");
        game.logged_in = false;
    }
}

async function get_user_card() {
    if (!game.alias)
        return;

    try{
        const uri = '/api/record/statistic/' + game.alias;
        const response = await fetch(uri);

        if (!response.ok)
            throw new Error("Error: failed to get user card.");

        const resp = await response.json();
        updateUserProfileCard(resp.data);
    }
    catch(e)
    {
        const default_user_card = {
            alias: game.alias,
            score: 0,
            rank: -1,
            rate: 0,
            wins: 0,
            losses: 0,
            total_matches: 0
        }

        updateUserProfileCard(default_user_card);
        console.log("info [client] No game card data was fetched.");
    }
}

async function auth_check(event: MouseEvent)
{
    event.preventDefault();
    const form = event.target;
    const username = (document.getElementById('username') as HTMLInputElement)!.value;
    const password = (document.getElementById('password') as HTMLInputElement)!.value;
    const body = {username: username, password: password};
    game.username = username;

    try {
        const res = await fetch("/api/auth", {
            method: "POST",
            headers: { 'Content-Type': 'application/json'},
            body: JSON.stringify(body),
            credentials: 'include'
        });

        if (!res.ok){
            throw new Error("Error: wrong response from server!")
        }

        const data = await res.json();

        if (data.evt === "login_state") {
            if (data.success === true)
            {
                navigate_to("middlePrepare");
                await get_alias(username);

                await get_user_card();
                init_msg_socket();
                game.logged_in = true;
                game.state2fa = false;
            }
            else if (data.require2FA)
            {
                game.state2fa = data.require2FA;
                navigate_to("login-2fa");
            }
            else
            {
                game.state2fa = false;
                navigate_to("login-fail");
                game.username = "";
            }
        }
        else
        {
            navigate_to("login-fail");
            game.username = "";
            console.log("info [client]: Error: wrong response format.");
        }

    }
    catch (err)
    {
        console.log("info [client]: Error: login failed.", err);
        navigate_to("login-fail");
    }
}

async function verify2FA(event: SubmitEvent) {
    event.preventDefault();
    const code = (document.getElementById("twofa-code") as HTMLInputElement)!.value;

    try {
        const res = await fetch("/api/2fa/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: 'include',
            body: JSON.stringify({ username: game.username, token: code })
        });

        const data = await res.json();

        if (data.success) {
            navigate_to("middlePrepare");
            await get_alias(game.username);
            await get_user_card();
            init_msg_socket();
            game.logged_in = true;
            game.state2fa = true;
        } else {
            showCustomAlert("Invalid 2FA code");
            game.username = "";
            game.state2fa = true;
            navigate_to("login");
        }
    } catch (err) {
        console.log("2FA verification error", err);
        showCustomAlert("Server error");
        game.username = "";
        game.state2fa = true;
    }
}

interface CredentialResponse {
  credential: string;
  select_by?: string;        
}

async function googleAuth(token: string) {
    try{
        const response = await fetch('/api/auth/google', {
            method: "POST",
            headers: {
                "Content_type": "application/json" },
            body: JSON.stringify({token: token}),
        });

        if (!response.ok)
            throw new Error("Wrong response from server");
        const data = await response.json();

        if (data.evt === "login_state_google")
        {
            if (data.success)
            {
                await get_alias(data.username);
                await get_user_card();
                init_msg_socket();
                game.logged_in = true;
                
                document.getElementById('user-name')!.innerHTML = game.alias;
                game.left = game.alias;

                (document.getElementById('user-avatar')! as HTMLImageElement).src = '/api/avatar/' + game.alias;

                navigate_to("middlePrepare");
            }
            else
            {
                navigate_to("login-fail");
                game.username = "";
            }
            return;
        }
        navigate_to("login-fail");
        game.username = "";
    }
    catch(e)
    {
        console.log("info [client]", e);
        navigate_to("login-fail");
        game.username = "";
    }
}

async function handleCredentialResponse(response: CredentialResponse){
    const token = response.credential;

    await googleAuth(token);
}

