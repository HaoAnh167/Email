const express = require("express");
const mysql = require("mysql2/promise");
const cookieParser = require("cookie-parser");
const multer = require("multer");

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});
const upload = multer({ storage: storage });

const app = express();
const port = 8000;

const pool = mysql.createPool({
  host: "localhost",
  // user: "wpr",
  // password: "fit2023",
  user: "root",
  password: "hao12471",
  database: "wpr2023",
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});
const db = pool;
module.exports = db;

app.set("view engine", "ejs");

// Middleware for parsing URL-encoded data and JSON
app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static("uploads"));

// Middleware for authentication
function requireAuth(req, res, next) {
  if (!req.cookies.userId) {
    return res.status(403).render("error", { error: "Error: Access Denied" });
  }
  next();
}

async function initializeDatabase() {
  try {
    // Create Users table
    const createUsersTableQuery = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
      );
    `;

    // Create Emails table
    const createEmailsTableQuery = `
      CREATE TABLE IF NOT EXISTS emails (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_id INT,
        receiver_id INT,
        subject VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        attachment VARCHAR(255), 
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
      );
    `;

    await db.query(createUsersTableQuery);
    console.log("Users table created");

    await db.query(createEmailsTableQuery);
    console.log("Emails table created");
    const initializeUsersQuery = `
      INSERT INTO users (username, email, password, full_name) VALUES
        ('user1', 'a@a.com', 'password1', 'fullname1'),
        ('user2', 'b@b.com', 'password2', 'fullname2'),
        ('user3', 'c@c.com', 'password3', 'fullname3');
      `;

    await db.query(initializeUsersQuery);
    console.log("Users data initialized");

    // Initialize Emails data
    const initializeEmailsQuery = `
      INSERT INTO emails (sender_id, receiver_id, subject, message) VALUES
        (1, 2, 'Subject 1', 'Message 1'),
        (2, 1, 'Subject 2', 'Message 2'),
        (2, 3, 'Subject 3', 'Message 3'),
        (3, 1, 'Subject 4', 'Message 4'),
        (1, 3, 'Subject 5', 'Message 5'),
        (3, 2, 'Subject 6', 'Message 6'),
        (2, 1, 'Subject 7', 'Message 7'),
        (3, 1, 'Subject 8', 'Message 8');
    `;

    await db.query(initializeEmailsQuery);
    console.log("Emails data initialized");

    console.log("Data initialized successfully");
  } catch (error) {
    console.error("Error initializing database:", error);
    throw error;
  }
}

// Call the initializeDatabase function
initializeDatabase();

// Sign-in
app.get(["/", "/signin"], (req, res) => {
  if (req.cookies.userId) {
    return res.redirect("/inbox");
  }

  res.render("signin", { error: null });
});

// Handle sign-in
app.post("/", async (req, res) => {
  const { username, password } = req.body;

  const user = await getUserByUsername(username);

  if (!user || password !== user.password) {
    return res.render("signin", { error: "Invalid username or password" });
  }

  res.cookie("userId", user.id);

  res.redirect("/inbox");
});

// Sign-up
app.get("/signup", (req, res) => {
  // if (req.cookies.userId) {
  //   return res.redirect("/inbox");
  // }

  res.render("signup", { error: null });
});

// Handle sign-up
app.post("/signup", async (req, res) => {
  const { fullname, email, username, password, confirmPassword } = req.body;

  if (!fullname || !email || !password || !confirmPassword || !username) {
    return res.render("signup", { error: "All fields are required" });
  }

  const existingUserEmail = await getUserByEmail(email);
  if (existingUserEmail) {
    return res.render("signup", { error: "Email address is already in use" });
  }

  const existingUserName = await getUserByUsername(username);
  if (existingUserName) {
    return res.render("signup", { error: "Username is already in use" });
  }

  if (password.length < 6) {
    return res.render("signup", {
      error: "Password must be at least 6 characters long",
    });
  }

  if (password !== confirmPassword) {
    return res.render("signup", { error: "Passwords do not match" });
  }

  await createUser(fullname, email, username, password);

  res.render("welcome");
});

// Inbox
app.get("/inbox", requireAuth, async (req, res) => {
  try {
    const page = req.query.page || 1;
    const currentPage = parseInt(page);
    const userId = req.cookies.userId;

    const emails = await getPaginatedReceivedEmails(userId, currentPage);
    const totalPages = await getTotalReceivedEmailPages(userId);
    const userFullName = await getUserFullNameById(userId);

    res.render("inbox", { emails, currentPage, totalPages, userFullName });
  } catch (error) {
    console.error("Error in /inbox route:", error);
    res.status(500).render("error", { error: "Internal Server Error" });
  }
});

// Outbox
app.get("/outbox", requireAuth, async (req, res) => {
  try {
    const page = req.query.page || 1;
    const currentPage = parseInt(page);
    const userId = req.cookies.userId;

    const sentEmails = await getPaginatedSentEmails(userId, currentPage);
    const totalPages = await getTotalSentEmailPages(userId);
    const userFullName = await getUserFullNameById(userId);

    res.render("outbox", { sentEmails, currentPage, totalPages, userFullName });
  } catch (error) {
    console.error("Error in /outbox route:", error);
    res.status(500).render("error", { error: "Internal Server Error" });
  }
});

app.get("/access-denied", (req, res) => {
  res.status(403).render("error", { error: "Access Denied: Please sign in." });
});

// Delete emails API
app.post("/delete-emails", requireAuth, async (req, res) => {
  const { emailIds } = req.body;
  const userId = req.cookies.userId;

  if (!userId) {
    return res
      .status(403)
      .json({ success: false, error: "Error: Access Denied" });
  }

  try {
    await deleteEmails(userId, emailIds);

    res.json({ success: true });
  } catch (error) {
    console.error("Error in /delete-emails route:", error);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

async function deleteEmails(userId, emailIds) {
  try {
    const queryString = `
        DELETE FROM emails
        WHERE (receiver_id = ? OR sender_id = ?) AND id IN (?);
      `;

    await db.query(queryString, [userId, userId, emailIds]);

    console.log(`Deleted emails with IDs: ${emailIds}`);
  } catch (error) {
    console.error("Error deleting emails:", error);
    throw error;
  }
}

async function getUserByUsername(username) {
  let connection;
  try {
    connection = await db.getConnection();
    const [rows, fields] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    return rows.length > 0 ? rows[0] : null;
  } catch (error) {
    console.error("Error fetching user:", error);
    throw error;
  } finally {
    if (connection) {
      connection.release();
    }
  }
}

async function getUserByEmail(email) {
  try {
    const [rows, fields] = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    return rows.length > 0 ? rows[0] : null;
  } catch (error) {
    console.error("Error fetching user:", error);
    throw error;
  }
}

async function createUser(fullname, email, username, password) {
  try {
    const [rows, fields] = await db.query(
      "INSERT INTO users (full_name, email, username, password) VALUES (?, ?, ?, ?)",
      [fullname, email, username, password]
    );
  } catch (error) {
    console.error("Error creating user:", error);
    throw error;
  }
}

async function getAllUsers() {
  try {
    const [rows, fields] = await db.query("SELECT id, full_name FROM users");
    return rows;
  } catch (error) {
    console.error("Error fetching users:", error);
    throw error;
  }
}

// Email Detail
app.get("/email/:id", requireAuth, async (req, res) => {
  try {
    const emailId = req.params.id;
    const email = await getEmailById(emailId);
    const userId = req.cookies.userId;

    const userFullName = await getUserFullNameById(userId);
    if (!email) {
      return res.status(404).render("error", { error: "Email not found" });
    }

    res.render("emailDetail", { email, userFullName });
  } catch (error) {
    console.error("Error in /email/:id route:", error);
    res.status(500).render("error", { error: "Internal Server Error" });
  }
});

async function getEmailById(emailId) {
  try {
    const emailQuery = "SELECT * FROM emails WHERE id = ?";
    const [emailRows, emailFields] = await db.query(emailQuery, [emailId]);

    if (emailRows.length === 0) {
      return null;
    }

    const email = emailRows[0];

    const senderQuery = "SELECT * FROM users WHERE id = ?";
    const [senderRows, senderFields] = await db.query(senderQuery, [
      email.sender_id,
    ]);

    const receiverQuery = "SELECT * FROM users WHERE id = ?";
    const [receiverRows, receiverFields] = await db.query(receiverQuery, [
      email.receiver_id,
    ]);

    email.senderEmail = senderRows.length > 0 ? senderRows[0].email : null;
    email.receiverEmail =
      receiverRows.length > 0 ? receiverRows[0].email : null;

    return email;
  } catch (error) {
    console.error("Error fetching email by ID:", error);
    throw error;
  }
}

async function getPaginatedSentEmails(userId, page) {
  const pageSize = 5;
  const offset = (page - 1) * pageSize;

  const query = `
    SELECT 
      emails.*,
      receiver.full_name AS receiverFullName
    FROM 
      emails
    JOIN 
      users AS receiver ON emails.receiver_id = receiver.id
    WHERE 
      emails.sender_id = ? 
    ORDER BY 
      sent_at DESC 
    LIMIT ?, ?;
  `;

  const [rows, fields] = await db.query(query, [userId, offset, pageSize]);

  return rows;
}

async function getPaginatedReceivedEmails(userId, page) {
  const pageSize = 5;
  const offset = (page - 1) * pageSize;

  const query = `
    SELECT 
      emails.*,
      sender.full_name AS senderFullName
    FROM 
      emails
    JOIN 
      users AS sender ON emails.sender_id = sender.id
    WHERE 
      emails.receiver_id = ? 
    ORDER BY 
      sent_at DESC 
    LIMIT ?, ?;
  `;

  const [rows, fields] = await db.query(query, [userId, offset, pageSize]);

  return rows;
}

async function getTotalReceivedEmailPages(userId) {
  try {
    const pageSize = 5;
    const [result] = await db.query(
      "SELECT COUNT(*) as total FROM emails WHERE receiver_id = ?",
      [userId]
    );
    const totalEmails = result[0].total;
    const totalPages = Math.ceil(totalEmails / pageSize);
    return totalPages;
  } catch (error) {
    console.error("Error getting total sent email pages:", error);
    throw error;
  }
}

async function getTotalSentEmailPages(userId) {
  try {
    const pageSize = 5;
    const [result] = await db.query(
      "SELECT COUNT(*) as total FROM emails WHERE sender_id = ?",
      [userId]
    );
    const totalEmails = result[0].total;
    const totalPages = Math.ceil(totalEmails / pageSize);
    return totalPages;
  } catch (error) {
    console.error("Error getting total sent email pages:", error);
    throw error;
  }
}

// Compose
app.get("/compose", requireAuth, async (req, res) => {
  try {
    const userId = req.cookies.userId;

    const users = await getAllUsers();
    const userFullName = await getUserFullNameById(userId);

    res.render("compose", { users, userFullName });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).render("error", { error: "Internal Server Error" });
  }
});

// Handle email composition and sending
app.post(
  "/compose",
  requireAuth,
  upload.single("attachment"),
  async (req, res) => {
    const users = await getAllUsers();
    const userId = req.cookies.userId;
    const userFullName = await getUserFullNameById(userId);
    const { recipient, subject, body } = req.body;

    if (!recipient) {
      return res.render("compose", {
        users,
        userFullName,
        error: "Please select a recipient.",
      });
    }

    // Send the email
    try {
      const attachment = req.file ? req.file.filename : null;
      const userId = req.cookies.userId;
      const userFullName = await getUserFullNameById(userId);

      await sendEmail(req.cookies.userId, recipient, subject, body, attachment);
      res.render("compose", {
        users,
        userFullName,
        success: "Email sent successfully!",
      });
    } catch (error) {
      console.error("Error sending email:", error);
      res.status(500).render("error", { error: "Internal Server Error" });
    }
  }
);

async function sendEmail(senderId, receiverId, subject, body, attachment) {
  try {
    const queryString = `
      INSERT INTO emails (sender_id, receiver_id, subject, message, attachment)
      VALUES (?, ?, ?, ?, ?);
    `;
    await db.query(queryString, [
      senderId,
      receiverId,
      subject,
      body,
      attachment,
    ]);
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
}

async function getUserFullNameById(userId) {
  try {
    const query = "SELECT full_name FROM users WHERE id = ?";
    const [rows, fields] = await db.query(query, [userId]);

    if (rows.length > 0) {
      return rows[0].full_name;
    }

    return null;
  } catch (error) {
    console.error("Error fetching user full name by ID:", error);
    throw error;
  }
}

app.get("/download/:filename", async (req, res) => {
  const filename = req.params.filename;

  if (!filename) {
    return res.status(400).send("Missing filename parameter");
  }

  res.redirect(`/uploads/${filename}`);
});

// Sign-out
app.get("/sign-out", (req, res) => {
  res.clearCookie("userId");

  res.redirect("/signin");
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
