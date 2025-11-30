import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";

dotenv.config();

const app = express();

app.use(express.json());
app.use(cookieParser());

// CORS SETTINGS — super important for GitHub Pages
app.use(cors({
    origin: process.env.CLIENT_ORIGIN,
    credentials: true
}));

const users = [
    {
        username: process.env.ADMIN_USER,
        passwordHash: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10)
    }
];

function createToken(username) {
    return jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "2h" });
}

function auth(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Not logged in" });

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: "Invalid token" });
    }
}

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
        return res.status(401).json({ error: "Wrong credentials" });
    }

    const token = createToken(username);

    res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none"
    });

    return res.json({ message: "Logged in!" });
});

app.get("/protected", auth, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}` });
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
