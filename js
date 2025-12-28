export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cookie = request.headers.get("Cookie") || "";

    // Konfigurasi: Halaman yang ingin dikunci
    const protectedPaths = ["https://www.nuhid.web.id/p/about.html", "/p/materi-khusus.html"];
    const isProtected = protectedPaths.some(path => url.pathname.includes(path));

    // --- 1. ENDPOINT PENDAFTARAN ---
    if (url.pathname === "/api/register" && request.method === "POST") {
      const { username, password } = await request.json();
      
      if (!username || !password) {
        return new Response(JSON.stringify({ message: "Data tidak lengkap" }), { status: 400 });
      }

      // Cek apakah user sudah ada di KV
      const userExists = await env.USER_DATA.get(username);
      if (userExists) {
        return new Response(JSON.stringify({ message: "Username sudah digunakan" }), { status: 400 });
      }

      // Simpan ke KV
      await env.USER_DATA.put(username, password);
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }

    // --- 2. ENDPOINT LOGIN ---
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      const storedPassword = await env.USER_DATA.get(username);

      if (storedPassword && storedPassword === password) {
        // Berikan Cookie Sesi (Berlaku 24 Jam)
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: {
            "Set-Cookie": "session_token=valid_user; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax",
            "Content-Type": "application/json"
          }
        });
      }
      return new Response(JSON.stringify({ message: "Username/Password salah" }), { status: 401 });
    }

    // --- 3. PROTEKSI HALAMAN (GATEKEEPER) ---
    if (isProtected) {
      if (!cookie.includes("session_token=valid_user")) {
        // Jika tidak punya cookie, lempar ke halaman login
        return Response.redirect(`${url.origin}/p/login.html`, 302);
      }
    }

    // Biarkan akses ke file asli Blogspot jika lolos pengecekan
    return fetch(request);
  }
};
    
