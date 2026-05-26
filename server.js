const express    = require('express');
const mongoose   = require('mongoose');
const multer     = require('multer');
const cors       = require('cors');
const path       = require('path');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const dns = require('dns');
 dns.setServers(["1.1.1.1","8.8.8.8"]);

require('dotenv').config();

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'digiseva_secret_2024';

// ── Nodemailer (Gmail) ────────────────────────────────
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS
//   }
// });

// const transporter = nodemailer.createTransport({
//   host: 'smtp.gmail.com',
//   port: 465,
//   secure: true,
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS
//   },
//   tls: {
//     rejectUnauthorized: false
//   }
// });

const transporter = nodemailer.createTransport({
  host:   'smtp-relay.brevo.com',
  port:   587,
  secure: false,
  auth: {
    user: process.env.BREVO_USER,   // your Brevo login email
    pass: process.env.BREVO_PASS    // Brevo SMTP key
  }
});

transporter.verify((err) => {
  if (err) console.log('❌ Email error:', err.message);
  else     console.log('✅ Email (Gmail) ready to send');
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── MongoDB ───────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/cybercafe_pan';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err));

// ── Cloudinary ────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

function extractPublicId(url) {
  if (!url) return null;
  try {
    const withoutQuery = url.split('?')[0];
    const uploadIdx = withoutQuery.indexOf('/upload/');
    if (uploadIdx === -1) return null;
    let after = withoutQuery.slice(uploadIdx + 8);
    after = after.replace(/^v\d+\//, '');
    const dotIdx = after.lastIndexOf('.');
    if (dotIdx !== -1) after = after.slice(0, dotIdx);
    return after;
  } catch { return null; }
}

async function deleteFromCloudinary(url) {
  if (!url) return;
  const publicId = extractPublicId(url);
  if (!publicId) return;
  try {
    await cloudinary.uploader.destroy(publicId);
  } catch (err) {
    console.warn(`⚠️ Cloudinary delete failed:`, err.message);
  }
}

// ── Schemas ───────────────────────────────────────────

const agentSchema = new mongoose.Schema({
  name:            { type: String, required: true },
  email:           { type: String, required: true, unique: true },
  phone:           { type: String, required: true },
  password:        { type: String, required: true },
  isApproved:      { type: Boolean, default: false },
  resetOTP:        { type: String },
  resetOTPExpiry:  { type: Date },
  registeredAt:    { type: Date, default: Date.now }
});
const Agent = mongoose.model('Agent', agentSchema);

const applicationSchema = new mongoose.Schema({
  agentId:           { type: mongoose.Schema.Types.ObjectId, ref: 'Agent', required: true },
  agentName:         { type: String, required: true },
  fullName:          { type: String, required: true },
  fatherName:        { type: String, required: true },
  dob:               { type: String, required: true },
  gender:            { type: String, required: true },
  phone:             { type: String, required: true },
  email:             { type: String },
  address:           { type: String, required: true },
  city:              { type: String, required: true },
  state:             { type: String, required: true },
  pincode:           { type: String, required: true },
  aadhaarFront:      { type: String },
  aadhaarBack:       { type: String },
  signature:         { type: String },
  photograph:        { type: String },
  paymentAmount:     { type: Number, default: 299 },
  paymentScreenshot: { type: String },
  paymentStatus:     { type: String, default: 'Unpaid' },
  status:            { type: String, default: 'Pending' },
  receipt:           { type: String },
  ownerComment:      { type: String, default: '' },
  commentUpdatedAt:  { type: Date },
  submittedAt:       { type: Date, default: Date.now }
});
const Application = mongoose.model('Application', applicationSchema);

// ── Multer + Cloudinary ───────────────────────────────
const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: 'pan-cafe',
    resource_type: 'auto',
    public_id: `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`
  })
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ── JWT Middleware ─────────────────────────────────────
function verifyAgent(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.agent = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── AGENT AUTH ────────────────────────────────────────

// Register
app.post('/api/agent/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password)
      return res.status(400).json({ error: 'All fields are required' });
    const exists = await Agent.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const agent  = new Agent({ name, email, phone, password: hashed });
    await agent.save();
    res.json({ success: true, message: 'Registration successful! Please wait for owner approval.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/agent/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const agent = await Agent.findOne({ email });
    if (!agent) return res.status(400).json({ error: 'Email not registered' });
    const match = await bcrypt.compare(password, agent.password);
    if (!match) return res.status(400).json({ error: 'Incorrect password' });
    if (!agent.isApproved)
      return res.status(403).json({ error: 'Your account is pending approval by the owner. Please wait.' });
    const token = jwt.sign(
      { id: agent._id, name: agent.name, email: agent.email },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ success: true, token, agent: { id: agent._id, name: agent.name, email: agent.email, phone: agent.phone } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Me
app.get('/api/agent/me', verifyAgent, async (req, res) => {
  try {
    const agent = await Agent.findById(req.agent.id).select('-password');
    if (!agent) return res.status(404).json({ error: 'Not found' });
    res.json(agent);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── FORGOT PASSWORD ───────────────────────────────────

// Send OTP via email
app.post('/api/agent/forgot-password', async (req, res) => {
  try {
    const { email, phone } = req.body;
    if (!email || !phone) return res.status(400).json({ error: 'Email and phone are required' });
    const agent = await Agent.findOne({ email });
    if (!agent) return res.status(404).json({ error: 'No account found with this email' });
    if (agent.phone !== phone) return res.status(400).json({ error: 'Phone number does not match our records' });

    const otp    = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 15 * 60 * 1000);
    agent.resetOTP       = otp;
    agent.resetOTPExpiry = expiry;
    await agent.save();

    await transporter.sendMail({
      from:    `"DigiSeva Cyber Café" <${process.env.EMAIL_USER}>`,
      to:      agent.email,
      subject: 'Password Reset OTP — DigiSeva Cyber Café',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;">
          <div style="text-align:center;margin-bottom:20px;">
            <h2 style="color:#0a1628;font-size:22px;margin:0">🖥️ DigiSeva Cyber Café</h2>
            <p style="color:#6b7280;font-size:13px;margin-top:4px">PAN Card Agent Portal</p>
          </div>
          <p style="color:#1a2332;font-size:15px">Hello <strong>${agent.name}</strong>,</p>
          <p style="color:#1a2332;font-size:14px">We received a request to reset your password. Use the OTP below:</p>
          <div style="background:#f0fdf4;border:2px solid #86efac;border-radius:12px;padding:20px;text-align:center;margin:20px 0;">
            <p style="color:#6b7280;font-size:12px;margin:0 0 6px;font-weight:600;letter-spacing:1px;">YOUR OTP / आपका OTP</p>
            <p style="font-size:38px;font-weight:900;letter-spacing:10px;color:#059669;margin:0;">${otp}</p>
            <p style="color:#6b7280;font-size:12px;margin:8px 0 0;">⏱ Valid for <strong>15 minutes</strong> only</p>
          </div>
          <p style="color:#1a2332;font-size:14px;">Enter this OTP on the website to set your new password.</p>
          <p style="color:#dc2626;font-size:13px;font-weight:600;">⚠️ Do not share this OTP with anyone. / किसी को न बताएं।</p>
          <hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0;">
          <p style="color:#9ca3af;font-size:12px;text-align:center;">
            If you did not request this, please ignore this email.<br>
            © 2026 DigiSeva Cyber Café — By Avdhesh Kumar
          </p>
        </div>
      `
    });

    console.log(`📧 OTP email sent to ${agent.email}`);
    res.json({ success: true, message: `OTP sent to ${agent.email}. Check your inbox.` });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
  }
});

// Reset password with OTP
app.post('/api/agent/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword)
      return res.status(400).json({ error: 'All fields are required' });
    const agent = await Agent.findOne({ email });
    if (!agent) return res.status(404).json({ error: 'Account not found' });
    if (!agent.resetOTP) return res.status(400).json({ error: 'No OTP requested. Please request again.' });
    if (agent.resetOTP !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    if (new Date() > agent.resetOTPExpiry) return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    agent.password       = await bcrypt.hash(newPassword, 10);
    agent.resetOTP       = undefined;
    agent.resetOTPExpiry = undefined;
    await agent.save();
    res.json({ success: true, message: 'Password reset successful! You can now login.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── APPLICATION ROUTES ─────────────────────────────────

// Submit new application
app.post('/api/apply', verifyAgent, upload.fields([
  { name: 'aadhaarFront', maxCount: 1 },
  { name: 'aadhaarBack',  maxCount: 1 },
  { name: 'signature',    maxCount: 1 },
  { name: 'photograph',   maxCount: 1 }
]), async (req, res) => {
  try {
    const data = { ...req.body, agentId: req.agent.id, agentName: req.agent.name };
    if (req.files['aadhaarFront']) data.aadhaarFront = req.files['aadhaarFront'][0].path;
    if (req.files['aadhaarBack'])  data.aadhaarBack  = req.files['aadhaarBack'][0].path;
    if (req.files['signature'])    data.signature    = req.files['signature'][0].path;
    if (req.files['photograph'])   data.photograph   = req.files['photograph'][0].path;
    const doc = new Application(data);
    await doc.save();
    res.json({ success: true, id: doc._id });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Edit existing application (agent can update text fields + optionally replace files)
app.patch('/api/apply/:id', verifyAgent, upload.fields([
  { name: 'aadhaarFront', maxCount: 1 },
  { name: 'aadhaarBack',  maxCount: 1 },
  { name: 'signature',    maxCount: 1 },
  { name: 'photograph',   maxCount: 1 }
]), async (req, res) => {
  try {
    const doc = await Application.findOne({ _id: req.params.id, agentId: req.agent.id });
    if (!doc) return res.status(404).json({ error: 'Application not found' });

    // Only allow editing if NOT fully verified
    if (doc.paymentStatus === 'Verified' && doc.status === 'Approved')
      return res.status(403).json({ error: 'Cannot edit a fully verified and approved application.' });

    // Update text fields
    const fields = ['fullName','fatherName','dob','gender','phone','email','address','city','state','pincode'];
    fields.forEach(f => { if (req.body[f] !== undefined) doc[f] = req.body[f]; });

    // Replace files only if new ones uploaded
    if (req.files['aadhaarFront']) {
      await deleteFromCloudinary(doc.aadhaarFront);
      doc.aadhaarFront = req.files['aadhaarFront'][0].path;
    }
    if (req.files['aadhaarBack']) {
      await deleteFromCloudinary(doc.aadhaarBack);
      doc.aadhaarBack = req.files['aadhaarBack'][0].path;
    }
    if (req.files['signature']) {
      await deleteFromCloudinary(doc.signature);
      doc.signature = req.files['signature'][0].path;
    }
    if (req.files['photograph']) {
      await deleteFromCloudinary(doc.photograph);
      doc.photograph = req.files['photograph'][0].path;
    }

    await doc.save();
    res.json({ success: true, id: doc._id });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Upload payment screenshot
app.post('/api/payment/:id', verifyAgent, upload.single('paymentScreenshot'), async (req, res) => {
  try {
    const doc = await Application.findOne({ _id: req.params.id, agentId: req.agent.id });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (doc.paymentScreenshot) await deleteFromCloudinary(doc.paymentScreenshot);
    doc.paymentScreenshot = req.file.path;
    doc.paymentStatus = 'Pending';
    await doc.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Agent's own applications
app.get('/api/agent/applications', verifyAgent, async (req, res) => {
  try {
    const apps = await Application.find({ agentId: req.agent.id }).sort({ submittedAt: -1 });
    res.json(apps);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── OWNER ROUTES ──────────────────────────────────────

app.get('/api/applications', async (req, res) => {
  try {
    const filter = {};
    if (req.query.agentId) filter.agentId = req.query.agentId;
    const apps = await Application.find(filter).sort({ submittedAt: -1 });
    res.json(apps);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/agents', async (req, res) => {
  try {
    const agents = await Agent.find().select('-password -resetOTP -resetOTPExpiry').sort({ registeredAt: -1 });
    res.json(agents);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/agents/:id/approve', async (req, res) => {
  try {
    const agent = await Agent.findByIdAndUpdate(
      req.params.id, { isApproved: req.body.isApproved }, { new: true }
    ).select('-password');
    res.json(agent);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/applications/:id', async (req, res) => {
  try {
    const doc = await Application.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/applications/:id/status', async (req, res) => {
  try {
    const doc = await Application.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/applications/:id/payment', async (req, res) => {
  try {
    const doc = await Application.findByIdAndUpdate(req.params.id, { paymentStatus: req.body.paymentStatus }, { new: true });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/applications/:id/comment', async (req, res) => {
  try {
    const doc = await Application.findByIdAndUpdate(
      req.params.id,
      { ownerComment: req.body.comment, commentUpdatedAt: new Date() },
      { new: true }
    );
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/receipt/:id', upload.single('receipt'), async (req, res) => {
  try {
    const doc = await Application.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (doc.status !== 'Approved') return res.status(400).json({ error: 'Only for Approved applications' });
    if (doc.receipt) await deleteFromCloudinary(doc.receipt);
    doc.receipt = req.file.path;
    await doc.save();
    res.json({ success: true, receiptUrl: doc.receipt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/stats/payments', async (req, res) => {
  try {
    const all      = await Application.find();
    const verified = all.filter(a => a.paymentStatus === 'Verified');
    const pending  = all.filter(a => a.paymentStatus === 'Pending');
    res.json({
      total:          all.length,
      verified:       verified.length,
      pending:        pending.length,
      unpaid:         all.filter(a => a.paymentStatus === 'Unpaid').length,
      totalCollected: verified.reduce((s, a) => s + (a.paymentAmount || 299), 0),
      pendingAmount:  pending.reduce((s, a) => s + (a.paymentAmount || 299), 0)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/applications/:id', async (req, res) => {
  try {
    const doc = await Application.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (doc.paymentStatus === 'Verified' && doc.status === 'Approved')
      return res.status(403).json({ error: 'Cannot delete a fully verified & approved application.' });
    await Promise.all([
      deleteFromCloudinary(doc.aadhaarFront),
      deleteFromCloudinary(doc.aadhaarBack),
      deleteFromCloudinary(doc.signature),
      deleteFromCloudinary(doc.photograph),
      deleteFromCloudinary(doc.paymentScreenshot),
      deleteFromCloudinary(doc.receipt)
    ]);
    await Application.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));


// const express    = require('express');
// const mongoose   = require('mongoose');
// const multer     = require('multer');
// const cors       = require('cors');
// const path       = require('path');
// const bcrypt     = require('bcryptjs');
// const jwt        = require('jsonwebtoken');
// const nodemailer = require('nodemailer');
// const dns = require('dns');
//  dns.setServers(["1.1.1.1","8.8.8.8"]);

// require('dotenv').config();

// const cloudinary = require('cloudinary').v2;
// const { CloudinaryStorage } = require('multer-storage-cloudinary');

// const app  = express();
// const PORT = process.env.PORT || 3000;
// const JWT_SECRET = process.env.JWT_SECRET || 'digiseva_secret_2024';

// // ── Email: Gmail for localhost, Resend for Railway ────
// const IS_PRODUCTION = !!process.env.RESEND_API_KEY;

// // Gmail transporter (localhost only)
// let gmailTransporter = null;
// if (!IS_PRODUCTION && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
//   gmailTransporter = nodemailer.createTransport({
//     host:   'smtp.gmail.com',
//     port:   587,
//     secure: false,
//     auth: {
//       user: process.env.EMAIL_USER,
//       pass: process.env.EMAIL_PASS
//     },
//     tls: { rejectUnauthorized: false },
//     family: 4
//   });
//   gmailTransporter.verify((err) => {
//     if (err) console.log('❌ Gmail error:', err.message);
//     else     console.log('✅ Gmail SMTP ready (localhost mode)');
//   });
// }

// if (IS_PRODUCTION) {
//   console.log('✅ Resend API ready (production mode)');
// }

// // Universal send function
// async function sendOTPEmail(toEmail, toName, otp) {
//   const html = `
//     <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;">
//       <div style="text-align:center;margin-bottom:20px;">
//         <h2 style="color:#0a1628;font-size:22px;margin:0">🖥️ DigiSeva Cyber Café</h2>
//         <p style="color:#6b7280;font-size:13px;margin-top:4px">PAN Card Agent Portal</p>
//       </div>
//       <p style="color:#1a2332;font-size:15px">Hello <strong>${toName}</strong>,</p>
//       <p style="color:#1a2332;font-size:14px">We received a request to reset your password. Use the OTP below:</p>
//       <div style="background:#f0fdf4;border:2px solid #86efac;border-radius:12px;padding:20px;text-align:center;margin:20px 0;">
//         <p style="color:#6b7280;font-size:12px;margin:0 0 6px;font-weight:600;letter-spacing:1px;">YOUR OTP / आपका OTP</p>
//         <p style="font-size:38px;font-weight:900;letter-spacing:10px;color:#059669;margin:0;">${otp}</p>
//         <p style="color:#6b7280;font-size:12px;margin:8px 0 0;">⏱ Valid for <strong>15 minutes</strong> only</p>
//       </div>
//       <p style="color:#1a2332;font-size:14px;">Enter this OTP on the website to reset your password.</p>
//       <p style="color:#dc2626;font-size:13px;font-weight:600;">⚠️ Do not share this OTP with anyone. / किसी को न बताएं।</p>
//       <hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0;">
//       <p style="color:#9ca3af;font-size:12px;text-align:center;">
//         © 2026 DigiSeva Cyber Café — By Avdhesh Kumar
//       </p>
//     </div>`;

//   if (IS_PRODUCTION) {
//     // ── Resend (Railway / Production) ──────────────────
//     const res = await fetch('https://api.resend.com/emails', {
//       method:  'POST',
//       headers: {
//         'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
//         'Content-Type':  'application/json'
//       },
//       body: JSON.stringify({
//         from:    'DigiSeva Cyber Café <onboarding@resend.dev>',
//         to:      [toEmail],
//         subject: 'Password Reset OTP — DigiSeva Cyber Café',
//         html
//       })
//     });
//     const data = await res.json();
//     if (!res.ok) throw new Error(data.message || 'Resend API error');
//     console.log(`✅ OTP sent to ${toEmail} via Resend`);

//   } else {
//     // ── Gmail SMTP (Localhost) ──────────────────────────
//     if (!gmailTransporter) {
//       throw new Error('EMAIL_USER and EMAIL_PASS not set in .env for localhost');
//     }
//     await gmailTransporter.sendMail({
//       from:    `"DigiSeva Cyber Café" <${process.env.EMAIL_USER}>`,
//       to:      toEmail,
//       subject: 'Password Reset OTP — DigiSeva Cyber Café',
//       html
//     });
//     console.log(`✅ OTP sent to ${toEmail} via Gmail`);
//   }
// }

// app.use(cors());
// app.use(express.json());
// app.use(express.static(path.join(__dirname, 'public')));

// // ── MongoDB ───────────────────────────────────────────
// const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/cybercafe_pan';
// mongoose.connect(MONGO_URI)
//   .then(() => console.log('✅ MongoDB connected'))
//   .catch(err => console.log('❌ MongoDB error:', err));

// // ── Cloudinary ────────────────────────────────────────
// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key:    process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET
// });

// function extractPublicId(url) {
//   if (!url) return null;
//   try {
//     const withoutQuery = url.split('?')[0];
//     const uploadIdx = withoutQuery.indexOf('/upload/');
//     if (uploadIdx === -1) return null;
//     let after = withoutQuery.slice(uploadIdx + 8);
//     after = after.replace(/^v\d+\//, '');
//     const dotIdx = after.lastIndexOf('.');
//     if (dotIdx !== -1) after = after.slice(0, dotIdx);
//     return after;
//   } catch { return null; }
// }

// async function deleteFromCloudinary(url) {
//   if (!url) return;
//   const publicId = extractPublicId(url);
//   if (!publicId) return;
//   try {
//     await cloudinary.uploader.destroy(publicId);
//   } catch (err) {
//     console.warn(`⚠️ Cloudinary delete failed:`, err.message);
//   }
// }

// // ── Schemas ───────────────────────────────────────────
// const agentSchema = new mongoose.Schema({
//   name:           { type: String, required: true },
//   email:          { type: String, required: true, unique: true },
//   phone:          { type: String, required: true },
//   password:       { type: String, required: true },
//   isApproved:     { type: Boolean, default: false },
//   resetOTP:       { type: String },
//   resetOTPExpiry: { type: Date },
//   registeredAt:   { type: Date, default: Date.now }
// });
// const Agent = mongoose.model('Agent', agentSchema);

// const applicationSchema = new mongoose.Schema({
//   agentId:           { type: mongoose.Schema.Types.ObjectId, ref: 'Agent', required: true },
//   agentName:         { type: String, required: true },
//   fullName:          { type: String, required: true },
//   fatherName:        { type: String, required: true },
//   dob:               { type: String, required: true },
//   gender:            { type: String, required: true },
//   phone:             { type: String, required: true },
//   email:             { type: String },
//   address:           { type: String, required: true },
//   city:              { type: String, required: true },
//   state:             { type: String, required: true },
//   pincode:           { type: String, required: true },
//   aadhaarFront:      { type: String },
//   aadhaarBack:       { type: String },
//   signature:         { type: String },
//   photograph:        { type: String },
//   paymentAmount:     { type: Number, default: 399 },
//   paymentScreenshot: { type: String },
//   paymentStatus:     { type: String, default: 'Unpaid' },
//   status:            { type: String, default: 'Pending' },
//   receipt:           { type: String },
//   ownerComment:      { type: String, default: '' },
//   commentUpdatedAt:  { type: Date },
//   submittedAt:       { type: Date, default: Date.now }
// });
// const Application = mongoose.model('Application', applicationSchema);

// // ── Multer + Cloudinary ───────────────────────────────
// const storage = new CloudinaryStorage({
//   cloudinary,
//   params: async (req, file) => ({
//     folder: 'pan-cafe',
//     resource_type: 'auto',
//     public_id: `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`
//   })
// });
// const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// // ── JWT Middleware ─────────────────────────────────────
// function verifyAgent(req, res, next) {
//   const auth = req.headers.authorization;
//   if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
//   try {
//     req.agent = jwt.verify(auth.split(' ')[1], JWT_SECRET);
//     next();
//   } catch {
//     res.status(401).json({ error: 'Invalid or expired token' });
//   }
// }

// // ── AGENT AUTH ────────────────────────────────────────

// app.post('/api/agent/register', async (req, res) => {
//   try {
//     const { name, email, phone, password } = req.body;
//     if (!name || !email || !phone || !password)
//       return res.status(400).json({ error: 'All fields are required' });
//     const exists = await Agent.findOne({ email });
//     if (exists) return res.status(400).json({ error: 'Email already registered' });
//     const hashed = await bcrypt.hash(password, 10);
//     const agent  = new Agent({ name, email, phone, password: hashed });
//     await agent.save();
//     res.json({ success: true, message: 'Registration successful! Please wait for owner approval.' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post('/api/agent/login', async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     const agent = await Agent.findOne({ email });
//     if (!agent) return res.status(400).json({ error: 'Email not registered' });
//     const match = await bcrypt.compare(password, agent.password);
//     if (!match) return res.status(400).json({ error: 'Incorrect password' });
//     if (!agent.isApproved)
//       return res.status(403).json({ error: 'Your account is pending approval by the owner. Please wait.' });
//     const token = jwt.sign(
//       { id: agent._id, name: agent.name, email: agent.email },
//       JWT_SECRET,
//       { expiresIn: '12h' }
//     );
//     res.json({ success: true, token, agent: { id: agent._id, name: agent.name, email: agent.email, phone: agent.phone } });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.get('/api/agent/me', verifyAgent, async (req, res) => {
//   try {
//     const agent = await Agent.findById(req.agent.id).select('-password');
//     if (!agent) return res.status(404).json({ error: 'Not found' });
//     res.json(agent);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // ── FORGOT PASSWORD ───────────────────────────────────

// app.post('/api/agent/forgot-password', async (req, res) => {
//   try {
//     const { email, phone } = req.body;
//     if (!email || !phone) return res.status(400).json({ error: 'Email and phone are required' });
//     const agent = await Agent.findOne({ email });
//     if (!agent) return res.status(404).json({ error: 'No account found with this email' });
//     if (agent.phone !== phone) return res.status(400).json({ error: 'Phone number does not match our records' });

//     const otp    = Math.floor(100000 + Math.random() * 900000).toString();
//     const expiry = new Date(Date.now() + 15 * 60 * 1000);
//     agent.resetOTP       = otp;
//     agent.resetOTPExpiry = expiry;
//     await agent.save();

//     await sendOTPEmail(agent.email, agent.name, otp);
//     res.json({ success: true, message: `OTP sent to ${agent.email}. Check your inbox.` });
//   } catch (err) {
//     console.error('Forgot password error:', err.message);
//     res.status(500).json({ error: 'Failed to send OTP email: ' + err.message });
//   }
// });

// app.post('/api/agent/reset-password', async (req, res) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword)
//       return res.status(400).json({ error: 'All fields are required' });
//     const agent = await Agent.findOne({ email });
//     if (!agent) return res.status(404).json({ error: 'Account not found' });
//     if (!agent.resetOTP) return res.status(400).json({ error: 'No OTP requested. Please request again.' });
//     if (agent.resetOTP !== otp) return res.status(400).json({ error: 'Invalid OTP' });
//     if (new Date() > agent.resetOTPExpiry) return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
//     if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

//     agent.password       = await bcrypt.hash(newPassword, 10);
//     agent.resetOTP       = undefined;
//     agent.resetOTPExpiry = undefined;
//     await agent.save();
//     res.json({ success: true, message: 'Password reset successful! You can now login.' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // ── APPLICATION ROUTES ─────────────────────────────────

// app.post('/api/apply', verifyAgent, upload.fields([
//   { name: 'aadhaarFront', maxCount: 1 },
//   { name: 'aadhaarBack',  maxCount: 1 },
//   { name: 'signature',    maxCount: 1 },
//   { name: 'photograph',   maxCount: 1 }
// ]), async (req, res) => {
//   try {
//     const data = { ...req.body, agentId: req.agent.id, agentName: req.agent.name };
//     if (req.files['aadhaarFront']) data.aadhaarFront = req.files['aadhaarFront'][0].path;
//     if (req.files['aadhaarBack'])  data.aadhaarBack  = req.files['aadhaarBack'][0].path;
//     if (req.files['signature'])    data.signature    = req.files['signature'][0].path;
//     if (req.files['photograph'])   data.photograph   = req.files['photograph'][0].path;
//     const doc = new Application(data);
//     await doc.save();
//     res.json({ success: true, id: doc._id });
//   } catch (err) {
//     res.status(500).json({ success: false, message: err.message });
//   }
// });

// app.patch('/api/apply/:id', verifyAgent, upload.fields([
//   { name: 'aadhaarFront', maxCount: 1 },
//   { name: 'aadhaarBack',  maxCount: 1 },
//   { name: 'signature',    maxCount: 1 },
//   { name: 'photograph',   maxCount: 1 }
// ]), async (req, res) => {
//   try {
//     const doc = await Application.findOne({ _id: req.params.id, agentId: req.agent.id });
//     if (!doc) return res.status(404).json({ error: 'Application not found' });
//     if (doc.paymentStatus === 'Verified' && doc.status === 'Approved')
//       return res.status(403).json({ error: 'Cannot edit a fully verified and approved application.' });
//     const fields = ['fullName','fatherName','dob','gender','phone','email','address','city','state','pincode'];
//     fields.forEach(f => { if (req.body[f] !== undefined) doc[f] = req.body[f]; });
//     if (req.files['aadhaarFront']) { await deleteFromCloudinary(doc.aadhaarFront); doc.aadhaarFront = req.files['aadhaarFront'][0].path; }
//     if (req.files['aadhaarBack'])  { await deleteFromCloudinary(doc.aadhaarBack);  doc.aadhaarBack  = req.files['aadhaarBack'][0].path; }
//     if (req.files['signature'])    { await deleteFromCloudinary(doc.signature);    doc.signature    = req.files['signature'][0].path; }
//     if (req.files['photograph'])   { await deleteFromCloudinary(doc.photograph);   doc.photograph   = req.files['photograph'][0].path; }
//     await doc.save();
//     res.json({ success: true, id: doc._id });
//   } catch (err) {
//     res.status(500).json({ success: false, message: err.message });
//   }
// });

// app.post('/api/payment/:id', verifyAgent, upload.single('paymentScreenshot'), async (req, res) => {
//   try {
//     const doc = await Application.findOne({ _id: req.params.id, agentId: req.agent.id });
//     if (!doc) return res.status(404).json({ error: 'Not found' });
//     if (doc.paymentScreenshot) await deleteFromCloudinary(doc.paymentScreenshot);
//     doc.paymentScreenshot = req.file.path;
//     doc.paymentStatus = 'Pending';
//     await doc.save();
//     res.json({ success: true });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.get('/api/agent/applications', verifyAgent, async (req, res) => {
//   try {
//     const apps = await Application.find({ agentId: req.agent.id }).sort({ submittedAt: -1 });
//     res.json(apps);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // ── OWNER ROUTES ──────────────────────────────────────

// app.get('/api/applications', async (req, res) => {
//   try {
//     const filter = {};
//     if (req.query.agentId) filter.agentId = req.query.agentId;
//     const apps = await Application.find(filter).sort({ submittedAt: -1 });
//     res.json(apps);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.get('/api/agents', async (req, res) => {
//   try {
//     const agents = await Agent.find().select('-password -resetOTP -resetOTPExpiry').sort({ registeredAt: -1 });
//     res.json(agents);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.patch('/api/agents/:id/approve', async (req, res) => {
//   try {
//     const agent = await Agent.findByIdAndUpdate(req.params.id, { isApproved: req.body.isApproved }, { new: true }).select('-password');
//     res.json(agent);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.get('/api/applications/:id', async (req, res) => {
//   try {
//     const doc = await Application.findById(req.params.id);
//     if (!doc) return res.status(404).json({ error: 'Not found' });
//     res.json(doc);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.patch('/api/applications/:id/status', async (req, res) => {
//   try {
//     const doc = await Application.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
//     res.json(doc);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.patch('/api/applications/:id/payment', async (req, res) => {
//   try {
//     const doc = await Application.findByIdAndUpdate(req.params.id, { paymentStatus: req.body.paymentStatus }, { new: true });
//     res.json(doc);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.patch('/api/applications/:id/comment', async (req, res) => {
//   try {
//     const doc = await Application.findByIdAndUpdate(
//       req.params.id,
//       { ownerComment: req.body.comment, commentUpdatedAt: new Date() },
//       { new: true }
//     );
//     if (!doc) return res.status(404).json({ error: 'Not found' });
//     res.json(doc);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post('/api/receipt/:id', upload.single('receipt'), async (req, res) => {
//   try {
//     const doc = await Application.findById(req.params.id);
//     if (!doc) return res.status(404).json({ error: 'Not found' });
//     if (doc.status !== 'Approved') return res.status(400).json({ error: 'Only for Approved applications' });
//     if (doc.receipt) await deleteFromCloudinary(doc.receipt);
//     doc.receipt = req.file.path;
//     await doc.save();
//     res.json({ success: true, receiptUrl: doc.receipt });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.get('/api/stats/payments', async (req, res) => {
//   try {
//     const all      = await Application.find();
//     const verified = all.filter(a => a.paymentStatus === 'Verified');
//     const pending  = all.filter(a => a.paymentStatus === 'Pending');
//     res.json({
//       total:          all.length,
//       verified:       verified.length,
//       pending:        pending.length,
//       unpaid:         all.filter(a => a.paymentStatus === 'Unpaid').length,
//       totalCollected: verified.reduce((s, a) => s + (a.paymentAmount || 399), 0),
//       pendingAmount:  pending.reduce((s, a) => s + (a.paymentAmount || 399), 0)
//     });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.delete('/api/applications/:id', async (req, res) => {
//   try {
//     const doc = await Application.findById(req.params.id);
//     if (!doc) return res.status(404).json({ error: 'Not found' });
//     if (doc.paymentStatus === 'Verified' && doc.status === 'Approved')
//       return res.status(403).json({ error: 'Cannot delete a fully verified & approved application.' });
//     await Promise.all([
//       deleteFromCloudinary(doc.aadhaarFront),
//       deleteFromCloudinary(doc.aadhaarBack),
//       deleteFromCloudinary(doc.signature),
//       deleteFromCloudinary(doc.photograph),
//       deleteFromCloudinary(doc.paymentScreenshot),
//       deleteFromCloudinary(doc.receipt)
//     ]);
//     await Application.findByIdAndDelete(req.params.id);
//     res.json({ success: true });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));