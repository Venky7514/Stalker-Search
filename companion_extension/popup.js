(function () {
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");

  fetch("http://127.0.0.1:7878/", { method: "GET" })
    .then((r) => {
      if (r.ok) {
        dot.classList.add("online");
        text.textContent = "Local app running on 127.0.0.1:7878";
      } else {
        text.textContent = "Standby (start app via cargo run)";
      }
    })
    .catch(() => {
      text.textContent = "Standby (start app via cargo run)";
    });
})();
