import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const allowedOrigins = (
  process.env.CLIENT_ORIGINS ||
  (process.env.NODE_ENV === "production"
    ? ""
    : "http://localhost:5173,http://127.0.0.1:5173")
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET must be set in the environment.");
}

if (process.env.NODE_ENV === "production" && JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters in production.");
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      const error = new Error("Origin is not allowed by CORS.");
      error.status = 403;
      return callback(error);
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }),
);
app.use(helmet());
app.use(express.json({ limit: "1mb" }));

const respondWithServerError = (res, message, error) => {
  if (process.env.NODE_ENV === "production") {
    console.error(message, error instanceof Error ? error.name : "Unknown error");
  } else {
    console.error(message, error);
  }
  return res.status(500).json({ message });
};

const normalizeEmail = (email = "") => email.trim().toLowerCase();

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    status: {
      type: String,
      enum: ["pending", "approved", "blocked"],
      default: "pending",
    },
    token: {
      type: String,
      default: null,
    },
  },
  { timestamps: true },
);

userSchema.pre("save", async function hashPassword() {
  if (!this.isModified("password")) {
    return;
  }

  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = async function comparePassword(
  candidatePassword,
) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

const ensureDefaultAdmin = async () => {
  const adminEmail = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || "";

  if (!adminEmail && !adminPassword) {
    return;
  }

  if (!adminEmail || !adminPassword) {
    throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD must both be configured.");
  }

  const existingAdmin = await User.findOne({ email: adminEmail });

  if (existingAdmin) {
    existingAdmin.name =
      process.env.ADMIN_NAME || existingAdmin.name || "System Administrator";
    existingAdmin.email = adminEmail;
    existingAdmin.role = "admin";
    existingAdmin.status = "approved";

    const passwordMatches = await existingAdmin.comparePassword(adminPassword);
    if (!passwordMatches) {
      existingAdmin.password = adminPassword;
      await existingAdmin.save();
    }

    console.log(`Admin account confirmed: ${adminEmail}`);
    return;
  }

  const adminUser = await User.create({
    name: process.env.ADMIN_NAME || "System Administrator",
    email: adminEmail,
    password: adminPassword,
    role: "admin",
    status: "approved",
  });

  console.log(`Default admin created: ${adminUser.email}`);
};

let databaseConnectionPromise;
let adminInitializationPromise;

const ensureDatabaseConnected = async () => {
  if (!process.env.MONGODB_URL) {
    throw new Error("MONGODB_URL must be set in the environment.");
  }

  if (mongoose.connection.readyState !== 1) {
    if (mongoose.connection.readyState !== 2) {
      databaseConnectionPromise = undefined;
    }

    if (!databaseConnectionPromise) {
      databaseConnectionPromise = mongoose
        .connect(process.env.MONGODB_URL, {
          maxPoolSize: 10,
          serverSelectionTimeoutMS: 10000,
        })
        .then(() => {
          console.log("Connected to MongoDB");
        })
        .catch((error) => {
          databaseConnectionPromise = undefined;
          throw error;
        });
    }

    await databaseConnectionPromise;
  }

  if (!adminInitializationPromise) {
    adminInitializationPromise = ensureDefaultAdmin().catch((error) => {
      adminInitializationPromise = undefined;
      throw error;
    });
  }

  await adminInitializationPromise;
};

const connectToDatabase = async (req, res, next) => {
  try {
    await ensureDatabaseConnected();
    next();
  } catch (error) {
    console.error(
      "Database initialization failed:",
      error instanceof Error ? error.name : "Unknown error",
    );
    res.status(503).json({ message: "Database unavailable." });
  }
};

const fundSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      default: "",
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true },
);

fundSchema.index({ user: 1, createdAt: -1 });

const Fund = mongoose.model("Fund", fundSchema);

const lpSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    commitment: {
      type: Number,
      required: true,
    },
    dateOfJoin: {
      type: String,
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true },
);

const Lp = mongoose.model("Lp", lpSchema);

const closeSchema = new mongoose.Schema(
  {
    date: {
      type: String,
      required: true,
    },
    merged: {
      type: Boolean,
      default: false,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true },
);

closeSchema.index({ date: 1, user: 1 }, { unique: true });

const Close = mongoose.model("Close", closeSchema);

const companySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    requirement: {
      type: Number,
      required: true,
    },
    profit: {
      type: Number,
      default: 0,
    },
    sector: {
      type: String,
      default: "Other",
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true },
);

const Company = mongoose.model("Company", companySchema);

const signToken = (user) =>
  jwt.sign(
    {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
    },
    JWT_SECRET,
    { expiresIn: "7d" },
  );

const protect = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Authentication required." });
  }

  const token = authHeader.slice("Bearer ".length);
  let decoded;

  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token." });
  }

  const user = await User.findById(decoded.id);

  if (!user) {
    return res.status(401).json({ message: "User not found." });
  }

  if (!user.token || user.token !== token) {
    return res.status(401).json({ message: "Invalid or expired token." });
  }

  if (user.status === "pending") {
    return res.status(403).json({
      message: "Your account is pending admin approval.",
    });
  }

  if (user.status === "blocked") {
    return res.status(403).json({
      message:
        "Your account has been blocked. Please contact an administrator.",
    });
  }

  req.user = user;
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Access denied. Admin privileges required." });
  }

  next();
};

const syncUserCloseState = async (userId) => {
  const lps = await Lp.find({ user: userId }).select("dateOfJoin");

  const dates = [
    ...new Set(lps.map((lp) => lp.dateOfJoin).filter(Boolean)),
  ].sort((a, b) => new Date(a) - new Date(b));

  const existingCloses = await Close.find({ user: userId });
  const existingMap = new Map(
    existingCloses.map((close) => [close.date, close]),
  );

  for (let i = 0; i < dates.length; i += 1) {
    const date = dates[i];

    // Leave existing Close records—including merged state—unchanged.
    if (!existingMap.has(date)) {
      await Close.create({
        user: userId,
        date,
        // Only the very first Close ever created begins as merged.
        merged: existingCloses.length === 0 && i === 0,
      });
    }
  }

  const staleIds = existingCloses
    .filter((close) => !dates.includes(close.date))
    .map((close) => close._id);

  if (staleIds.length) {
    await Close.deleteMany({ _id: { $in: staleIds } });
  }

  return Close.find({ user: userId }).sort({ date: 1 });
};

const getUserCloses = async (userId) => {
  return Close.find({ user: userId }).sort({ date: 1 });
};

app.get("/", (req, res) => {
  res.send("Business Backend is running");
});

app.use("/api", connectToDatabase);

app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", database: "connected" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string" ||
      !name.trim() ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Name, email and password are required.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters long.",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const isAdminRegistration =
      normalizedEmail === normalizeEmail(process.env.ADMIN_EMAIL || "");

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res
        .status(409)
        .json({ message: "A user with this email already exists." });
    }

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password,
      status: isAdminRegistration ? "approved" : "pending",
      role: isAdminRegistration ? "admin" : "user",
    });

    res.status(201).json({
      message:
        "Registration successful. Your account is pending admin approval.",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
    });
  } catch (error) {
    respondWithServerError(res, "Failed to register user.", error);
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      !password
    ) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }

    const normalizedEmail = normalizeEmail(email);
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    if (user.status === "pending") {
      return res.status(403).json({
        message: "Your account is awaiting admin approval.",
      });
    }

    if (user.status === "blocked") {
      return res.status(403).json({
        message:
          "Your account has been blocked. Please contact an administrator.",
      });
    }

    const token = signToken(user);
    user.token = token;
    await user.save();

    res.status(200).json({
      message: "Login successful.",
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
    });
  } catch (error) {
    respondWithServerError(res, "Failed to login.", error);
  }
});

app.get("/api/auth/me", protect, async (req, res) => {
  res.status(200).json({
    user: {
      _id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      status: req.user.status,
    },
  });
});

app.post("/api/auth/logout", protect, async (req, res) => {
  try {
    req.user.token = null;
    await req.user.save();

    res.status(200).json({ message: "Logout successful." });
  } catch (error) {
    respondWithServerError(res, "Failed to log out.", error);
  }
});

app.get("/api/admin/users", protect, requireAdmin, async (req, res) => {
  try {
    const invalidUserIds = await User.find({
      $or: [
        { name: { $exists: false } },
        { name: null },
        { name: "" },
        { email: { $exists: false } },
        { email: null },
        { email: "" },
      ],
    }).select("_id");

    if (invalidUserIds.length > 0) {
      await User.deleteMany({
        _id: { $in: invalidUserIds.map((user) => user._id) },
      });
    }

    const users = await User.find({
      name: { $exists: true, $ne: null, $ne: "" },
      email: { $exists: true, $ne: null, $ne: "" },
    })
      .select("-password -token")
      .sort({ createdAt: -1 });

    res.status(200).json({ users });
  } catch (error) {
    respondWithServerError(res, "Failed to fetch users.", error);
  }
});

app.patch(
  "/api/admin/users/:id/status",
  protect,
  requireAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;
      const allowed = ["pending", "approved", "blocked"];

      if (!allowed.includes(status)) {
        return res.status(400).json({ message: "Invalid account status." });
      }

      const targetUser = await User.findById(req.params.id);

      if (!targetUser) {
        return res.status(404).json({ message: "User not found." });
      }

      if (
        String(targetUser._id) === String(req.user._id) &&
        status === "blocked"
      ) {
        return res
          .status(400)
          .json({ message: "You cannot block your own admin account." });
      }

      if (targetUser.role === "admin" && status === "blocked") {
        const otherAdmins = await User.find({
          role: "admin",
          status: "approved",
          _id: { $ne: targetUser._id },
        });

        if (otherAdmins.length === 0) {
          return res.status(400).json({
            message: "At least one active admin account must remain available.",
          });
        }
      }

      targetUser.status = status;
      await targetUser.save();

      res.status(200).json({
        message: `User status updated to ${status}.`,
        user: {
          _id: targetUser._id,
          name: targetUser.name,
          email: targetUser.email,
          role: targetUser.role,
          status: targetUser.status,
        },
      });
    } catch (error) {
      respondWithServerError(res, "Failed to update user status.", error);
    }
  },
);

app.get("/api/funds", protect, async (req, res) => {
  try {
    const funds = await Fund.find({ user: req.user._id }).sort({
      createdAt: -1,
    });
    res.status(200).json(funds);
  } catch (error) {
    respondWithServerError(res, "Failed to fetch funds.", error);
  }
});

app.post("/api/funds", protect, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Fund name is required." });
    }

    const fund = await Fund.create({
      name,
      description: description || "",
      user: req.user._id,
    });

    res.status(201).json({ message: "Fund created successfully.", fund });
  } catch (error) {
    respondWithServerError(res, "Failed to create fund.", error);
  }
});

app.get("/api/closes", protect, async (req, res) => {
  try {
    const closes = await getUserCloses(req.user._id);

    res.json({
      data: {
        mergedDates: closes
          .filter((close) => close.merged)
          .map((close) => close.date),
        closes,
      },
    });
  } catch (error) {
    respondWithServerError(res, "Failed to fetch closes.", error);
  }
});

app.post("/api/closes/merge", protect, async (req, res) => {
  try {
    const { date } = req.body;

    if (!date) {
      return res.status(400).json({ message: "Close date is required." });
    }
    const closes = await syncUserCloseState(req.user._id);
    const nextClose = closes.find((close, index) => index > 0 && !close.merged);

    if (!nextClose || nextClose.date !== date) {
      return res
        .status(400)
        .json({ message: "Only the next sequential close can be merged." });
    }

    nextClose.merged = true;
    await nextClose.save();
    const updatedCloses = await Close.find({ user: req.user._id }).sort({
      date: 1,
    });

    res.json({
      message: "Close merged successfully",
      data: {
        mergedDates: updatedCloses
          .filter((close) => close.merged)
          .map((close) => close.date),
        closes: updatedCloses,
      },
    });
  } catch (error) {
    respondWithServerError(res, "Failed to merge close.", error);
  }
});

app.get("/api/companies", protect, async (req, res) => {
  try {
    const companies = await Company.find({ user: req.user._id });
    res.status(200).json(companies);
  } catch (error) {
    respondWithServerError(res, "Failed to fetch companies.", error);
  }
});

app.post("/api/companies", protect, async (req, res) => {
  try {
    const { name, requirement, profit, sector, isActive } = req.body;

    if (!name || !requirement) {
      return res
        .status(400)
        .json({ message: "Company name and requirement are required." });
    }

    const newCompany = await Company.create({
      name,
      requirement: Number(requirement),
      profit: Number(profit || 0),
      sector: sector || "Other",
      isActive: isActive !== false,
      user: req.user._id,
    });

    res
      .status(201)
      .json({ message: "Company added successfully", company: newCompany });
  } catch (error) {
    respondWithServerError(res, "Failed to create company.", error);
  }
});

app.put("/api/companies/:id", protect, async (req, res) => {
  try {
    const company = await Company.findOne({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!company) {
      return res.status(404).json({ message: "Company not found." });
    }

    const allowedFields = [
      "name",
      "requirement",
      "profit",
      "sector",
      "isActive",
    ];

    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) {
        company[field] =
          field === "requirement" || field === "profit"
            ? Number(req.body[field])
            : req.body[field];
      }
    });

    await company.save();
    res.status(200).json({ message: "Company updated successfully", company });
  } catch (error) {
    respondWithServerError(res, "Failed to update company.", error);
  }
});

app.delete("/api/companies/:id", protect, async (req, res) => {
  try {
    const deletedCompany = await Company.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!deletedCompany) {
      return res.status(404).json({ message: "Company not found." });
    }

    res.status(200).json({ message: "Company deleted successfully" });
  } catch (error) {
    respondWithServerError(res, "Failed to delete company.", error);
  }
});

app.post("/api/lps", protect, async (req, res) => {
  try {
    const name = req.body.name ?? req.body.userName;
    const { commitment, dateOfJoin } = req.body;

    if (!name || !commitment || !dateOfJoin) {
      return res.status(400).json({
        message: "name (or userName), commitment and dateOfJoin are required",
      });
    }

    const savedLp = await Lp.create({
      name,
      commitment: Number(commitment),
      dateOfJoin,
      user: req.user._id,
    });

    await syncUserCloseState(req.user._id);

    res.status(201).json({ message: "LP saved successfully", data: savedLp });
  } catch (error) {
    respondWithServerError(res, "Failed to save LP.", error);
  }
});

app.get("/api/lps", protect, async (req, res) => {
  try {
    const lps = await Lp.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.status(200).json(lps);
  } catch (error) {
    respondWithServerError(res, "Failed to fetch LPs.", error);
  }
});

app.put("/api/lps/:id", protect, async (req, res) => {
  try {
    const lp = await Lp.findOne({ _id: req.params.id, user: req.user._id });

    if (!lp) {
      return res.status(404).json({ message: "LP not found." });
    }

    lp.name = req.body.name ?? lp.name;
    lp.commitment =
      req.body.commitment !== undefined
        ? Number(req.body.commitment)
        : lp.commitment;
    lp.dateOfJoin = req.body.dateOfJoin ?? lp.dateOfJoin;

    await lp.save();
    await syncUserCloseState(req.user._id);
    res.status(200).json(lp);
  } catch (error) {
    respondWithServerError(res, "Failed to update LP.", error);
  }
});

app.delete("/api/lps/:id", protect, async (req, res) => {
  try {
    const deletedLP = await Lp.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!deletedLP) {
      return res.status(404).json({ message: "LP not found." });
    }

    await syncUserCloseState(req.user._id);
    res.status(200).json({ message: "LP deleted successfully" });
  } catch (error) {
    respondWithServerError(res, "Failed to delete LP.", error);
  }
});

app.use((req, res) => {
  res.status(404).json({ message: "Not found." });
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  if (error.status === 400) {
    return res.status(400).json({ message: "Invalid request payload." });
  }

  if (error.status === 403) {
    return res.status(403).json({ message: "Origin is not allowed." });
  }

  if (process.env.NODE_ENV === "production") {
    console.error(
      "Unhandled request error:",
      error instanceof Error ? error.name : "Unknown error",
    );
  } else {
    console.error("Unhandled request error:", error);
  }
  return res.status(500).json({ message: "Internal server error." });
});

export default app;

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}
