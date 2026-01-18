function login() {
  const msg = document.getElementById("msg");

  fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: document.getElementById("email").value,
      password: document.getElementById("password").value
    })
  })
  .then(res => res.json())
  .then(data => {

    // 🔒 ACCOUNT LOCKED
    if (data.locked) {
      startCountdown(data.remaining, data.reason);
      return;
    }

    // 🔐 OTP REQUIRED
    if (data.otp_required) {
      window.location.href = "/otp";
      return;
    }

    msg.innerText = data.message || "Login failed";
  });
}

function startCountdown(seconds, reason) {
  const msg = document.getElementById("msg");
  let timeLeft = seconds;

  msg.style.color = "#f87171";

  const interval = setInterval(() => {
    msg.innerText =
      `${reason}\nAccount locked.\nTry again in ${timeLeft}s`;

    timeLeft--;

    if (timeLeft < 0) {
      clearInterval(interval);
      msg.style.color = "#22c55e";
      msg.innerText = "You can try logging in again.";
    }
  }, 1000);
}


// ------------------------------

function register() {
  const loader = document.getElementById("loader");
  const msg = document.getElementById("msg");

  // 🔄 SHOW LOADER (SAFE)
  if (loader) loader.style.display = "flex";
  if (msg) msg.innerText = "";

  fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: document.getElementById("email").value,
      password: document.getElementById("password").value
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      window.location.href = "/login";
    } else {
      if (msg) msg.innerText = data.message || "Registration failed";
      if (loader) loader.style.display = "none";
    }
  })
  .catch(() => {
    if (msg) msg.innerText = "Server error";
    if (loader) loader.style.display = "none";
  });
}

// ------------------------------

function verifyOtp() {
  const msg = document.getElementById("msg");

  fetch("/verify-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      otp: document.getElementById("otp").value
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      // ✅ REDIRECT AFTER OTP SUCCESS
      window.location.href = "/dashboard";
    } else {
      if (msg) msg.innerText = "Invalid OTP";
    }
  })
  .catch(() => {
    if (msg) msg.innerText = "Server error";
  });
}
