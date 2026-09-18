let watching = false
let pollInterval = null
let alerts = []
let maxPoints = 60

const ctx = document.getElementById("eventChart").getContext("2d")

const chart = new Chart(ctx, {
  type: "line",
  data: {
    labels: [],
    datasets: [{
      label: "Events/sec",
      data: [],
      borderColor: "#38bdf8",
      backgroundColor: "rgba(56,189,248,0.2)",
      fill: true,
      tension: 0.4,
      borderWidth: 2,
      pointRadius: 3,
      pointBackgroundColor: "#38bdf8",
      pointBorderColor: "#0b1120",
      pointBorderWidth: 1
    }]
  },
  options: {
    animation: { duration: 500, easing: "easeOutQuart" },
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: "#94a3b8" } } },
    scales: {
      x: { ticks: { color: "#64748b" }, grid: { color: "#1f2937" } },
      y: { beginAtZero: true, ticks: { color: "#64748b" }, grid: { color: "#1f2937" } }
    }
  }
})

function changeMode() {
  const mode = document.getElementById("modeSelect").value
  document.getElementById("watchControls").style.display = mode === "watch" ? "flex" : "none"
  document.getElementById("uploadControls").style.display = mode === "upload" ? "flex" : "none"
}

// ---- Chế độ Watch real-time ----
async function startWatch() {
  const path = document.getElementById("pathInput").value.trim()
  const logType = document.getElementById("logTypeSelect").value

  if (!path) {
    alert("Nhập đường dẫn file log cần theo dõi.")
    return
  }

  try {
    const res = await fetch("/watch/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, log_type: logType })
    })
    const data = await res.json()
    if (!res.ok) {
      alert("Không thể bắt đầu: " + (data.error || res.statusText))
      return
    }
  } catch (err) {
    alert("Lỗi kết nối tới backend: " + err)
    return
  }

  watching = true
  setStatus("Đang theo dõi", "status-running")
  document.getElementById("logTypeLabel").innerText = logType === "ssh" ? "SSH" : "Web"
  pollInterval = setInterval(pollBackend, 1000)
}

async function stopWatch() {
  watching = false
  clearInterval(pollInterval)
  setStatus("Đã dừng", "status-stopped")
  try {
    await fetch("/watch/stop", { method: "POST" })
  } catch (err) {
    console.error("Lỗi khi gọi /watch/stop:", err)
  }
}

// ---- Chế độ Upload file batch ----
async function uploadFile() {
  const fileInput = document.getElementById("fileInput")
  const logType = document.getElementById("logTypeSelect").value

  if (!fileInput.files.length) {
    alert("Chọn 1 file log để phân tích.")
    return
  }

  const formData = new FormData()
  formData.append("logfile", fileInput.files[0])
  formData.append("log_type", logType)

  setStatus("Đang phân tích...", "status-running")

  try {
    const res = await fetch("/analyze", { method: "POST", body: formData })
    const data = await res.json()
    if (!res.ok) {
      alert("Lỗi phân tích: " + (data.error || res.statusText))
      setStatus("Đã dừng", "status-stopped")
      return
    }
    document.getElementById("logTypeLabel").innerText = logType === "ssh" ? "SSH" : "Web"
    setStatus("Đã phân tích xong", "status-stopped")
    await refreshOnce()
  } catch (err) {
    alert("Lỗi kết nối tới backend: " + err)
    setStatus("Đã dừng", "status-stopped")
  }
}

function setStatus(text, cls) {
  const el = document.getElementById("statusLabel")
  el.innerText = text
  el.className = "value " + cls
}

async function clearSystem() {
  if (watching) await stopWatch()

  alerts = []
  document.getElementById("lineCount").innerText = 0
  document.getElementById("alertCount").innerText = 0
  document.getElementById("logTypeLabel").innerText = "-"
  setStatus("Chưa chạy", "status-stopped")

  chart.data.labels = []
  chart.data.datasets[0].data = []
  chart.update()

  updateTable()

  try {
    await fetch("/clear", { method: "POST" })
  } catch (err) {
    console.error("Lỗi khi gọi /clear:", err)
  }
}

function exportAlerts() {
  const fmt = document.getElementById("exportFormat").value
  window.location.href = `/export?format=${fmt}`
}

function updateTable() {
  const table = document.getElementById("alertTable")

  if (alerts.length === 0) {
    table.innerHTML = `<tr class="empty-row"><td colspan="5">Chưa có cảnh báo nào</td></tr>`
    return
  }

  table.innerHTML = ""
  alerts.forEach(a => {
    table.innerHTML += `
      <tr class="sev-${a.severity || "medium"}">
        <td>${a.ip}</td>
        <td>${a.rule}</td>
        <td><span class="sev-badge">${(a.severity || "medium").toUpperCase()}</span></td>
        <td class="detail-cell" title="${(a.detail || "").replace(/"/g, '&quot;')}">${a.detail || "-"}</td>
        <td>${a.time}</td>
      </tr>
    `
  })
}

async function refreshOnce() {
  try {
    const [statsRes, alertsRes] = await Promise.all([fetch("/stats"), fetch("/alerts")])
    const stats = await statsRes.json()
    const newAlerts = await alertsRes.json()

    document.getElementById("lineCount").innerText = stats.line_count

    const history = stats.history.slice(-maxPoints)
    chart.data.labels = history.map(h => h.time)
    chart.data.datasets[0].data = history.map(h => h.count)
    chart.update()

    alerts = newAlerts
    document.getElementById("alertCount").innerText = alerts.length
    updateTable()
  } catch (err) {
    console.error("Lỗi khi refresh:", err)
  }
}

async function pollBackend() {
  if (!watching) return
  await refreshOnce()

  const statsRes = await fetch("/stats")
  const stats = await statsRes.json()
  if (!stats.watching) {
    stopWatch()
  }
}

window.addEventListener("DOMContentLoaded", changeMode)
