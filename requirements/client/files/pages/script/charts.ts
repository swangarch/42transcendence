declare var Chart: any;

function create_chart(wins: number, losses: number)
{
    const ctx = (document.getElementById('user-Chart')! as HTMLCanvasElement).getContext('2d');
    let winLossChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['Wins', 'Losses'],
        datasets: [{
        data: [wins, losses],
        backgroundColor: ['#5cdb84ff', '#eb7965ff'],
        borderWidth: 0.5
        }]
    },
    options: {
            cutout: '80%',
            plugins: {
            legend: {
                display: false,
                labels: {
                color: 'white'
                }
            },
            tooltip: {
                    callbacks: {
                    label: function(context: any) {
                        const total = context.dataset.data.reduce((a : any, b: any) => a + b, 0);
                        const value = context.parsed;
                        const percent = ((value / total) * 100).toFixed(1);
                        return `${context.label}: ${value} (${percent}%)`;
                        }
                    }
                }
            }
        }
    });
    return winLossChart;
}

function create_friend_chart(wins: number, losses: number)
{
    if (wins === 0 && losses === 0)
        return;

    const canvas_Container = document.getElementById('friend-Chart-Container');
    if (!canvas_Container)
        return;
    canvas_Container.style.display = "flex";

    const canvas = document.getElementById('friend-Chart') as HTMLCanvasElement;
    if (!canvas)
        return;
    const ctx = canvas.getContext('2d');
    let winLossChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['Wins', 'Losses'],
        datasets: [{
        data: [wins, losses],
        backgroundColor: ['#5cdb84ff', '#eb7965ff'],
        borderWidth: 0.3
        }]
    },
    options: {
            cutout: '85%',
            plugins: {
            legend: {
                display: false,
                labels: {
                color: 'white'
                }
            },
            tooltip: {
                    callbacks: {
                    label: function(context: any) {
                        const total = context.dataset.data.reduce((a : any, b: any) => a + b, 0);
                        const value = context.parsed;
                        const percent = ((value / total) * 100).toFixed(1);
                        return `${context.label}: ${value} (${percent}%)`;
                        }
                    }
                }
            }
        }
    });
    return winLossChart;
}

var winLossChart : any = null;
var historyChart : any = null;

document.addEventListener('DOMContentLoaded', () => {
    winLossChart = create_chart(0, 1);
});

function update_history_chat()
{
    if (historyChart)
    {
        let labels: string[] = [];
        let dataPoints: number[] = [];
        let counter = 0;
        
        for (const match of matches)
        {
            counter++;
            if (match.result === "win")
            {
                labels.push(counter.toString());
                dataPoints.push(1);
            }
            else if (match.result === "loss")
            {
                labels.push(counter.toString());
                dataPoints.push(2);
            }
            
        }
        console.log(labels);
        console.log(dataPoints);
        historyChart.data.labels = labels;
        historyChart.data.datasets[0].data = dataPoints;
        historyChart.update();
    }
}

function update_chart(win:number, loss:number)
{
    if (winLossChart)
    {
        winLossChart.data.datasets[0].data = [win, loss];
        winLossChart.update();
    }
}