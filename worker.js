/*
  ZILNET WORKER
  Cloudflare Workers + D1
  D1 binding in wrangler.toml:
  DB
  This Worker provides:
  - Signup
  - Login
  - Logout
  - Current user
  - Posts
  - Likes
  - Comments
  - Jobs
  - Job applications
  - Follows
  - Notifications
  - Basic profile
*/
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8"
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}
function error(message, status = 400) {
  return json({
    ok: false,
    error: message
  }, status);
}
function randomId(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(bits))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const cookie of cookies.split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) {
      return decodeURIComponent(value.join("="));
    }
  }
  return null;
}
function sessionCookie(token) {
  return [
    `zilnet_session=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=2592000"
  ].join("; ");
}
function clearSessionCookie() {
  return [
    "zilnet_session=",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0"
  ].join("; ");
}
async function currentUser(request, env) {
  const token = getCookie(request, "zilnet_session");
  if (!token) {
    return null;
  }
  const result = await env.DB.prepare(`
    SELECT
      users.id,
      users.username,
      users.display_name,
      users.email,
      users.bio,
      users.avatar_url,
      users.created_at
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ?
      AND sessions.expires_at > ?
    LIMIT 1
  `)
    .bind(token, Date.now())
    .first();
  return result || null;
}
async function initializeDatabase(env) {
  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        bio TEXT DEFAULT '',
        avatar_url TEXT DEFAULT '',
        created_at INTEGER NOT NULL
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        content TEXT NOT NULL,
        media_url TEXT DEFAULT '',
        created_at INTEGER NOT NULL
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS likes (
        user_id TEXT NOT NULL,
        post_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, post_id)
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        post_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS follows (
        follower_id TEXT NOT NULL,
        following_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (follower_id, following_id)
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        company TEXT DEFAULT '',
        location TEXT DEFAULT '',
        created_at INTEGER NOT NULL
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS job_applications (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        message TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        UNIQUE(job_id, user_id)
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
      )
    `)
  ]);
}
async function handleHealth(env) {
  try {
    const result = await env.DB
      .prepare("SELECT 1 AS connected")
      .first();
    return json({
      ok: true,
      database: result?.connected === 1
        ? "connected"
        : "not connected"
    });
  } catch (e) {
    return error(e.message, 500);
  }
}
async function handleSignup(request, env) {
  const body = await request.json();
  const username = String(body.username || "")
    .trim()
    .toLowerCase();
  const displayName = String(
    body.displayName || username
  ).trim();
  const email = String(body.email || "")
    .trim()
    .toLowerCase();
  const password = String(body.password || "");
  if (!username || !email || !password) {
    return error("Username, email and password are required.");
  }
  if (username.length < 3) {
    return error("Username must contain at least 3 characters.");
  }
  if (password.length < 8) {
    return error("Password must contain at least 8 characters.");
  }
  const existing = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE username = ? OR email = ?
    LIMIT 1
  `)
    .bind(username, email)
    .first();
  if (existing) {
    return error("Username or email is already registered.", 409);
  }
  const userId = randomId(16);
  const salt = randomId(16);
  const passwordHash = await hashPassword(password, salt);
  const now = Date.now();
  await env.DB.prepare(`
    INSERT INTO users (
      id,
      username,
      display_name,
      email,
      password_hash,
      password_salt,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      userId,
      username,
      displayName,
      email,
      passwordHash,
      salt,
      now
    )
    .run();
  const token = randomId(32);
  await env.DB.prepare(`
    INSERT INTO sessions (
      token,
      user_id,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      token,
      userId,
      now + 2592000000,
      now
    )
    .run();
  return new Response(
    JSON.stringify({
      ok: true,
      user: {
        id: userId,
        username,
        displayName,
        email
      }
    }),
    {
      status: 201,
      headers: {
        ...JSON_HEADERS,
        "Set-Cookie": sessionCookie(token)
      }
    }
  );
}
async function handleLogin(request, env) {
  const body = await request.json();
  const identifier = String(
    body.identifier || body.username || body.email || ""
  )
    .trim()
    .toLowerCase();
  const password = String(body.password || "");
  if (!identifier || !password) {
    return error("Username/email and password are required.");
  }
  const user = await env.DB.prepare(`
    SELECT *
    FROM users
    WHERE username = ? OR email = ?
    LIMIT 1
  `)
    .bind(identifier, identifier)
    .first();
  if (!user) {
    return error("Invalid username/email or password.", 401);
  }
  const passwordHash = await hashPassword(
    password,
    user.password_salt
  );
  if (passwordHash !== user.password_hash) {
    return error("Invalid username/email or password.", 401);
  }
  const token = randomId(32);
  const now = Date.now();
  await env.DB.prepare(`
    INSERT INTO sessions (
      token,
      user_id,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      token,
      user.id,
      now + 2592000000,
      now
    )
    .run();
  return new Response(
    JSON.stringify({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.display_name,
        email: user.email,
        bio: user.bio,
        avatarUrl: user.avatar_url
      }
    }),
    {
      headers: {
        ...JSON_HEADERS,
        "Set-Cookie": sessionCookie(token)
      }
    }
  );
}
async function handleLogout(request, env) {
  const token = getCookie(request, "zilnet_session");
  if (token) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();
  }
  return new Response(
    JSON.stringify({
      ok: true
    }),
    {
      headers: {
        ...JSON_HEADERS,
        "Set-Cookie": clearSessionCookie()
      }
    }
  );
}
async function handleMe(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return json({
      loggedIn: false,
      user: null
    });
  }
  return json({
    loggedIn: true,
    user
  });
}
async function handleCreatePost(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const body = await request.json();
  const content = String(body.content || "").trim();
  const mediaUrl = String(body.mediaUrl || "").trim();
  if (!content && !mediaUrl) {
    return error("Post cannot be empty.");
  }
  if (content.length > 10000) {
    return error("Post is too long.");
  }
  const id = randomId(16);
  const now = Date.now();
  await env.DB.prepare(`
    INSERT INTO posts (
      id,
      user_id,
      content,
      media_url,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      user.id,
      content,
      mediaUrl,
      now
    )
    .run();
  return json({
    ok: true,
    post: {
      id,
      userId: user.id,
      content,
      mediaUrl,
      createdAt: now
    }
  }, 201);
}
async function handleGetPosts(env) {
  const result = await env.DB.prepare(`
    SELECT
      posts.id,
      posts.user_id AS userId,
      posts.content,
      posts.media_url AS mediaUrl,
      posts.created_at AS createdAt,
      users.username,
      users.display_name AS displayName,
      users.avatar_url AS avatarUrl,
      COUNT(DISTINCT likes.user_id) AS likeCount,
      COUNT(DISTINCT comments.id) AS commentCount
    FROM posts
    JOIN users
      ON users.id = posts.user_id
    LEFT JOIN likes
      ON likes.post_id = posts.id
    LEFT JOIN comments
      ON comments.post_id = posts.id
    GROUP BY posts.id
    ORDER BY posts.created_at DESC
    LIMIT 100
  `).all();
  return json({
    ok: true,
    posts: result.results || []
  });
}
async function handleLike(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const body = await request.json();
  const postId = String(body.postId || "");
  if (!postId) {
    return error("postId is required.");
  }
  const existing = await env.DB.prepare(`
    SELECT 1
    FROM likes
    WHERE user_id = ? AND post_id = ?
  `)
    .bind(user.id, postId)
    .first();
  if (existing) {
    await env.DB.prepare(`
      DELETE FROM likes
      WHERE user_id = ? AND post_id = ?
    `)
      .bind(user.id, postId)
      .run();
    return json({
      ok: true,
      liked: false
    });
  }
  await env.DB.prepare(`
    INSERT INTO likes (
      user_id,
      post_id,
      created_at
    )
    VALUES (?, ?, ?)
  `)
    .bind(
      user.id,
      postId,
      Date.now()
    )
    .run();
  return json({
    ok: true,
    liked: true
  });
}
async function handleComment(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const body = await request.json();
  const postId = String(body.postId || "");
  const content = String(body.content || "").trim();
  if (!postId || !content) {
    return error("Post and comment are required.");
  }
  const id = randomId(16);
  const now = Date.now();
  await env.DB.prepare(`
    INSERT INTO comments (
      id,
      post_id,
      user_id,
      content,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      postId,
      user.id,
      content,
      now
    )
    .run();
  return json({
    ok: true,
    comment: {
      id,
      postId,
      userId: user.id,
      content,
      createdAt: now
    }
  }, 201);
}
async function handleCreateJob(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const body = await request.json();
  const title = String(body.title || "").trim();
  const description = String(body.description || "").trim();
  const company = String(body.company || "").trim();
  const location = String(body.location || "").trim();
  if (!title || !description) {
    return error("Job title and description are required.");
  }
  const id = randomId(16);
  const now = Date.now();
  await env.DB.prepare(`
    INSERT INTO jobs (
      id,
      user_id,
      title,
      description,
      company,
      location,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      user.id,
      title,
      description,
      company,
      location,
      now
    )
    .run();
  return json({
    ok: true,
    job: {
      id,
      title,
      description,
      company,
      location,
      createdAt: now
    }
  }, 201);
}
async function handleGetJobs(env) {
  const result = await env.DB.prepare(`
    SELECT
      jobs.id,
      jobs.user_id AS userId,
      jobs.title,
      jobs.description,
      jobs.company,
      jobs.location,
      jobs.created_at AS createdAt,
      users.username,
      users.display_name AS displayName
    FROM jobs
    JOIN users
      ON users.id = jobs.user_id
    ORDER BY jobs.created_at DESC
    LIMIT 100
  `).all();
  return json({
    ok: true,
    jobs: result.results || []
  });
}
async function handleApplyJob(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const body = await request.json();
  const jobId = String(body.jobId || "");
  const message = String(body.message || "").trim();
  if (!jobId) {
    return error("jobId is required.");
  }
  const job = await env.DB.prepare(`
    SELECT id, user_id
    FROM jobs
    WHERE id = ?
  `)
    .bind(jobId)
    .first();
  if (!job) {
    return error("Job not found.", 404);
  }
  if (job.user_id === user.id) {
    return error("You cannot apply to your own job.");
  }
  const applicationId = randomId(16);
  const now = Date.now();
  try {
    await env.DB.prepare(`
      INSERT INTO job_applications (
        id,
        job_id,
        user_id,
        message,
        status,
        created_at
      )
      VALUES (?, ?, ?, ?, 'pending', ?)
    `)
      .bind(
        applicationId,
        jobId,
        user.id,
        message,
        now
      )
      .run();
  } catch (e) {
    if (e.message.includes("UNIQUE")) {
      return error("You already applied to this job.", 409);
    }
    throw e;
  }
  const notificationId = randomId(16);
  await env.DB.prepare(`
    INSERT INTO notifications (
      id,
      user_id,
      type,
      message,
      read,
      created_at
    )
    VALUES (?, ?, 'job_application', ?, 0, ?)
  `)
    .bind(
      notificationId,
      job.user_id,
      `${user.display_name} applied to your job.`,
      now
    )
    .run();
  return json({
    ok: true,
    application: {
      id: applicationId,
      jobId,
      status: "pending",
      createdAt: now
    }
  }, 201);
}
async function handleFollow(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const body = await request.json();
  const targetUserId = String(body.userId || "");
  if (!targetUserId) {
    return error("userId is required.");
  }
  if (targetUserId === user.id) {
    return error("You cannot follow yourself.");
  }
  const existing = await env.DB.prepare(`
    SELECT 1
    FROM follows
    WHERE follower_id = ? AND following_id = ?
  `)
    .bind(user.id, targetUserId)
    .first();
  if (existing) {
    await env.DB.prepare(`
      DELETE FROM follows
      WHERE follower_id = ? AND following_id = ?
    `)
      .bind(user.id, targetUserId)
      .run();
    return json({
      ok: true,
      following: false
    });
  }
  await env.DB.prepare(`
    INSERT INTO follows (
      follower_id,
      following_id,
      created_at
    )
    VALUES (?, ?, ?)
  `)
    .bind(
      user.id,
      targetUserId,
      Date.now()
    )
    .run();
  return json({
    ok: true,
    following: true
  });
}
async function handleProfile(request, env) {
  const username =
    new URL(request.url)
      .searchParams
      .get("username");
  if (!username) {
    return error("username is required.");
  }
  const user = await env.DB.prepare(`
    SELECT
      id,
      username,
      display_name AS displayName,
      bio,
      avatar_url AS avatarUrl,
      created_at AS createdAt
    FROM users
    WHERE username = ?
    LIMIT 1
  `)
    .bind(username.toLowerCase())
    .first();
  if (!user) {
    return error("User not found.", 404);
  }
  const counts = await env.DB.prepare(`
    SELECT
      (SELECT COUNT(*) FROM follows WHERE following_id = ?) AS followers,
      (SELECT COUNT(*) FROM follows WHERE follower_id = ?) AS following,
      (SELECT COUNT(*) FROM posts WHERE user_id = ?) AS posts
  `)
    .bind(user.id, user.id, user.id)
    .first();
  return json({
    ok: true,
    profile: {
      ...user,
      followers: counts?.followers || 0,
      following: counts?.following || 0,
      posts: counts?.posts || 0
    }
  });
}
async function handleNotifications(request, env) {
  const user = await currentUser(request, env);
  if (!user) {
    return error("You must be logged in.", 401);
  }
  const result = await env.DB.prepare(`
    SELECT
      id,
      type,
      message,
      read,
      created_at AS createdAt
    FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 100
  `)
    .bind(user.id)
    .all();
  return json({
    ok: true,
    notifications: result.results || []
  });
}
async function handleSearch(request, env) {
  const q =
    new URL(request.url)
      .searchParams
      .get("q");
  if (!q || q.trim().length < 1) {
    return json({
      ok: true,
      users: [],
      jobs: []
    });
  }
  const search = `%${q.trim()}%`;
  const users = await env.DB.prepare(`
    SELECT
      id,
      username,
      display_name AS displayName,
      bio,
      avatar_url AS avatarUrl
    FROM users
    WHERE username LIKE ?
       OR display_name LIKE ?
    ORDER BY username
    LIMIT 50
  `)
    .bind(search, search)
    .all();
  const jobs = await env.DB.prepare(`
    SELECT
      id,
      title,
      description,
      company,
      location,
      created_at AS createdAt
    FROM jobs
    WHERE title LIKE ?
       OR description LIKE ?
       OR company LIKE ?
    ORDER BY created_at DESC
    LIMIT 50
  `)
    .bind(search, search, search)
    .all();
  return json({
    ok: true,
    users: users.results || [],
    jobs: jobs.results || []
  });
}
async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  try {
    if (path === "/api/health" && request.method === "GET") {
      return handleHealth(env);
    }
    if (path === "/api/signup" && request.method === "POST") {
      return handleSignup(request, env);
    }
    if (path === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (path === "/api/logout" && request.method === "POST") {
      return handleLogout(request, env);
    }
    if (path === "/api/me" && request.method === "GET") {
      return handleMe(request, env);
    }
    if (path === "/api/posts" && request.method === "GET") {
      return handleGetPosts(env);
    }
    if (path === "/api/posts" && request.method === "POST") {
      return handleCreatePost(request, env);
    }
    if (path === "/api/like" && request.method === "POST") {
      return handleLike(request, env);
    }
    if (path === "/api/comments" && request.method === "POST") {
      return handleComment(request, env);
    }
    if (path === "/api/jobs" && request.method === "GET") {
      return handleGetJobs(env);
    }
    if (path === "/api/jobs" && request.method === "POST") {
      return handleCreateJob(request, env);
    }
    if (path === "/api/jobs/apply" && request.method === "POST") {
      return handleApplyJob(request, env);
    }
    if (path === "/api/follow" && request.method === "POST") {
      return handleFollow(request, env);
    }
    if (path === "/api/profile" && request.method === "GET") {
      return handleProfile(request, env);
    }
    if (path === "/api/notifications" && request.method === "GET") {
      return handleNotifications(request, env);
    }
    if (path === "/api/search" && request.method === "GET") {
      return handleSearch(request, env);
    }
    return error("API endpoint not found.", 404);
  } catch (e) {
    console.error("ZILNET API ERROR:", e);
    return error(
      "Internal server error.",
      500
    );
  }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    /*
      API requests go to the backend.
    */
    if (url.pathname.startsWith("/api/")) {
      return api(request, env);
    }
    /*
      Initialize the D1 tables.
      This is convenient for the first build.
      Later, we should move database creation
      into proper migrations.
    */
    try {
      await initializeDatabase(env);
    } catch (e) {
      console.error("D1 INITIALIZATION ERROR:", e);
      return new Response(
        "ZILNET database initialization failed: " + e.message,
        { status: 500 }
      );
    }
    /*
      Everything else is served by your
      Cloudflare Assets configuration.
    */
    return env.ASSETS.fetch(request);
  }
};
