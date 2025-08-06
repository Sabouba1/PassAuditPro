fetch("/static/data/eval_results.json")
  .then(res => {
    if (!res.ok) throw new Error("No evaluation data found.");
    return res.json();
  })
  .then(data => {
    if (!Array.isArray(data) || data.length === 0) throw new Error("Results are empty");

    let weakCount = 0, highRisk = 0, total = data.length;
    const strengthCount = { Weak: 0, Fair: 0, Strong: 0, "Very Strong": 0, Uncracked: 0 };
    const riskScores = [];

    data.forEach(([username, password, status, score]) => {
      strengthCount[status] = (strengthCount[status] || 0) + 1;

      if (status !== "Uncracked") {
        let risk = 0;
        let reasons = [];

        if (status === "Weak") {
          risk += 5;
          reasons.push("Weak password (+5)");
        } else if (status === "Fair") {
          risk += 2;
          reasons.push("Fair password (+2)");
        } else if (status === "Strong") {
          risk += 1;
          reasons.push("Strong but cracked (+1)");
        }

        if (
          typeof password === "string" &&
          typeof username === "string" &&
          password.toLowerCase().includes(username.toLowerCase())
        ) {
          risk += 3;
          reasons.push("Contains username (+3)");
        }

        if (risk >= 5) highRisk++;
        riskScores.push({ username, risk, reasons });
      }

      if (status === "Weak") weakCount++;
    });

    // Update KPI values with animation
    animateValue("weakPct", 0, ((weakCount / total) * 100).toFixed(1), 2000, "%");
    animateValue("highRisk", 0, highRisk, 2000);
    animateValue("totalUsers", 0, total, 2000);

    // Modern pie chart with % labels inside
    new Chart(document.getElementById("strengthChart"), {
      type: 'pie',
      data: {
        labels: Object.keys(strengthCount),
        datasets: [{
          data: Object.values(strengthCount),
          backgroundColor: [
            "#f44336",  // Weak
            "#ffca28",  // Fair
            "#66bb6a",  // Strong
            "#8e24aa",  // Very Strong
            "#9e9e9e"   // Uncracked
          ],
          borderColor: "#fff",
          borderWidth: 2
        }]
      },
      options: {
        plugins: {
          legend: {
            position: 'top',
            labels: {
              color: '#fff',
              font: { weight: '600' }
            }
          },
          datalabels: {
            color: '#fff',
            font: { weight: 'bold', size: 13 },
            formatter: (value, ctx) => {
              const total = ctx.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
              const percent = total ? (value / total * 100).toFixed(0) + "%" : "0%";
              return percent;
            }
          },
          title: {
            display: true,
            text: "Password Strength Distribution",
            color: "#fff",
            font: { size: 16, weight: "bold" }
          }
        }
      },
      plugins: [ChartDataLabels]
    });

    // Risk chart
    riskScores.sort((a, b) => b.risk - a.risk);
    if (riskScores.length === 0) {
      riskScores.push({ username: "No cracked users", risk: 0, reasons: [] });
    }

    new Chart(document.getElementById("riskChart"), {
      type: 'bar',
      data: {
        labels: riskScores.map(x => x.username),
        datasets: [{
          label: 'Risk Score',
          data: riskScores.map(x => x.risk),
          backgroundColor: '#f44336',
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        scales: {
          x: {
            ticks: { color: '#fff' },
            grid: { color: 'rgba(255,255,255,0.1)' }
          },
          y: {
            beginAtZero: true,
            ticks: { color: '#fff' },
            grid: { color: 'rgba(255,255,255,0.1)' }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (context) {
                const index = context.dataIndex;
                const item = riskScores[index];
                return [`Risk: ${item.risk}`, ...item.reasons];
              }
            }
          },
          title: {
            display: true,
            text: 'User Risk Levels',
            color: '#fff'
          }
        }
      }
    });

  })
  .catch(err => {
    console.warn("⚠️ Dashboard error:", err.message);
    document.getElementById("weakPct").innerText = "--%";
    document.getElementById("highRisk").innerText = "--";
    document.getElementById("totalUsers").innerText = "--";
  });


// Animate number utility
function animateValue(id, start, end, duration, suffix = '') {
  const el = document.getElementById(id);
  if (!el) return;

  start = Number(start);
  end = Number(end);

  const range = end - start;
  const minTimer = 30;
  const stepTime = Math.max(Math.abs(Math.floor(duration / range)), minTimer);
  let current = start;
  const increment = end > start ? 1 : -1;

  const timer = setInterval(() => {
    current += increment;
    el.textContent = current + suffix;
    if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
      clearInterval(timer);
      el.textContent = end + suffix;
    }
  }, stepTime);
}
