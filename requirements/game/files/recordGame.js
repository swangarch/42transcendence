async function save_game_record(body) {
    try{
        const res = await fetch("http://t_record:9431/internal/api/record/", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const info = await res.json();
            throw new Error(JSON.stringify(info) || 'failed to record game result');
        }

        const resp = await res.json();
    }
    catch (error)
    {
        console.log('info [game]:', error);
    }
}

exports.save_game_record = save_game_record;