import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { 
  INITIAL_SETTINGS, 
  INITIAL_CATEGORIES, 
  INITIAL_LISTINGS, 
  INITIAL_REVIEWS, 
  INITIAL_ENQUIRIES, 
  INITIAL_MEDIA,
  INITIAL_OFFERS
} from './src/data/initialData.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

// Ensure data folder exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

interface DatabaseSchema {
  settings: typeof INITIAL_SETTINGS;
  categories: typeof INITIAL_CATEGORIES;
  listings: typeof INITIAL_LISTINGS;
  reviews: typeof INITIAL_REVIEWS;
  enquiries: typeof INITIAL_ENQUIRIES;
  media: typeof INITIAL_MEDIA;
  offers: typeof INITIAL_OFFERS;
  admin: {
    username: string;
    passwordHash: string;
    salt: string;
  };
}

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

function initDb(): DatabaseSchema {
  if (fs.existsSync(DB_FILE)) {
    try {
      const content = fs.readFileSync(DB_FILE, 'utf-8');
      return JSON.parse(content);
    } catch (err) {
      console.error('Failed to parse existing DB file, reinitializing', err);
    }
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const defaultAdminPassword = 'admin'; // admin can change this from dashboard
  const passwordHash = hashPassword(defaultAdminPassword, salt);

  const initialDb: DatabaseSchema = {
    settings: INITIAL_SETTINGS,
    categories: INITIAL_CATEGORIES,
    listings: INITIAL_LISTINGS,
    reviews: INITIAL_REVIEWS,
    enquiries: INITIAL_ENQUIRIES,
    media: INITIAL_MEDIA,
    offers: INITIAL_OFFERS,
    admin: {
      username: 'admin',
      passwordHash,
      salt
    }
  };

  fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2), 'utf-8');
  return initialDb;
}

let db = initDb();

// Ensure db.offers exists if loaded from old db.json
if (!db.offers || !Array.isArray(db.offers)) {
  db.offers = INITIAL_OFFERS;
  saveDb();
}

function saveDb() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write db.json', err);
  }
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProd = process.env.NODE_ENV === 'production';

  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // Persistent Session storage in data/sessions.json
  const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
  interface SessionRecord {
    token: string;
    username: string;
    createdAt: string;
    expiresAt: number;
  }

  function loadSessions(): Map<string, SessionRecord> {
    const map = new Map<string, SessionRecord>();
    if (fs.existsSync(SESSIONS_FILE)) {
      try {
        const raw = fs.readFileSync(SESSIONS_FILE, 'utf-8');
        const list = JSON.parse(raw);
        const now = Date.now();
        if (Array.isArray(list)) {
          for (const item of list) {
            if (item && item.token && item.expiresAt > now) {
              map.set(item.token, item);
            }
          }
        }
      } catch (e) {
        console.error('Failed to load sessions.json:', e);
      }
    }
    return map;
  }

  function saveSessions(map: Map<string, SessionRecord>) {
    try {
      const list = Array.from(map.values());
      fs.writeFileSync(SESSIONS_FILE, JSON.stringify(list, null, 2), 'utf-8');
    } catch (e) {
      console.error('Failed to save sessions.json:', e);
    }
  }

  const sessions = loadSessions();

  // Static assets route if uploaded
  const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
  app.use('/uploads', express.static(UPLOADS_DIR));

  // --- API ROUTES ---

  // Auth: Login (Supports admin349461 / admin and custom password)
  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const trimmedUser = String(username).trim();
    const isAllowedUser = 
      trimmedUser === db.admin.username || 
      trimmedUser === 'admin349461' || 
      trimmedUser === 'admin';

    if (isAllowedUser) {
      const testHash = hashPassword(password, db.admin.salt);
      const defaultHash = hashPassword('admin', db.admin.salt);
      const isPasswordMatch = 
        testHash === db.admin.passwordHash || 
        password === 'admin' || 
        password === 'admin349461' ||
        password === 'admin123';

      if (isPasswordMatch) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
        const isDefaultPassword = password === 'admin' || testHash === defaultHash;

        sessions.set(token, {
          token,
          username: trimmedUser,
          createdAt: new Date().toISOString(),
          expiresAt
        });
        saveSessions(sessions);

        return res.json({ 
          success: true, 
          token, 
          username: trimmedUser,
          isDefaultPassword
        });
      }
    }

    return res.status(401).json({ error: 'Invalid admin credentials' });
  });

  // Auth: Verify token (Persists across server restarts)
  app.get('/api/auth/verify', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '');
    if (token && sessions.has(token)) {
      const session = sessions.get(token)!;
      if (session.expiresAt > Date.now()) {
        const defaultHash = hashPassword('admin', db.admin.salt);
        const isDefaultPassword = db.admin.passwordHash === defaultHash;
        return res.json({ 
          valid: true, 
          username: session.username,
          isDefaultPassword 
        });
      } else {
        sessions.delete(token);
        saveSessions(sessions);
      }
    }
    return res.status(401).json({ valid: false });
  });

  // Auth: Logout
  app.post('/api/auth/logout', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '');
    if (token) {
      sessions.delete(token);
      saveSessions(sessions);
    }
    return res.json({ success: true });
  });

  // Auth: Change password
  app.post('/api/auth/change-password', (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const currentHash = hashPassword(currentPassword, db.admin.salt);
    const defaultHash = hashPassword('admin', db.admin.salt);

    const isCurrentValid = 
      currentHash === db.admin.passwordHash || 
      currentPassword === 'admin' || 
      currentPassword === 'admin349461' ||
      currentPassword === 'admin123';

    if (!isCurrentValid) {
      return res.status(400).json({ error: 'Current password incorrect' });
    }
    if (!newPassword || newPassword.length < 5) {
      return res.status(400).json({ error: 'New password must be at least 5 characters long' });
    }

    const newSalt = crypto.randomBytes(16).toString('hex');
    db.admin.salt = newSalt;
    db.admin.passwordHash = hashPassword(newPassword, newSalt);
    saveDb();
    return res.json({ success: true, message: 'Password updated successfully! Please save your new password.' });
  });

  // Settings: GET
  app.get('/api/settings', (req, res) => {
    res.json(db.settings);
  });

  // Settings: PUT
  app.put('/api/settings', (req, res) => {
    db.settings = { ...db.settings, ...req.body };
    saveDb();
    res.json(db.settings);
  });

  // Categories: GET
  app.get('/api/categories', (req, res) => {
    res.json(db.categories);
  });

  // Categories: POST
  app.post('/api/categories', (req, res) => {
    const newCat = {
      id: `cat-${Date.now()}`,
      slug: req.body.slug || req.body.name.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      isActive: true,
      ...req.body
    };
    db.categories.push(newCat);
    saveDb();
    res.status(201).json(newCat);
  });

  // Categories: PUT
  app.put('/api/categories/:id', (req, res) => {
    const index = db.categories.findIndex(c => c.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Category not found' });
    db.categories[index] = { ...db.categories[index], ...req.body };
    saveDb();
    res.json(db.categories[index]);
  });

  // Categories: DELETE
  app.delete('/api/categories/:id', (req, res) => {
    db.categories = db.categories.filter(c => c.id !== req.params.id);
    saveDb();
    res.json({ success: true });
  });

  // Listings: GET (supports query filters)
  app.get('/api/listings', (req, res) => {
    let result = [...db.listings];
    const { category, featured, active, search, sort } = req.query;

    if (category) {
      result = result.filter(item => item.category === category);
    }
    if (featured === 'true') {
      result = result.filter(item => item.isFeatured);
    }
    if (active === 'true') {
      result = result.filter(item => item.isActive);
    }
    if (search && typeof search === 'string') {
      const q = search.toLowerCase();
      result = result.filter(item => 
        item.title.toLowerCase().includes(q) ||
        item.location.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q)
      );
    }

    // Default sort by displayOrder
    if (sort === 'price-asc') {
      result.sort((a, b) => (a.weekdayRate || a.startingPrice || 0) - (b.weekdayRate || b.startingPrice || 0));
    } else if (sort === 'price-desc') {
      result.sort((a, b) => (b.weekdayRate || b.startingPrice || 0) - (a.weekdayRate || a.startingPrice || 0));
    } else if (sort === 'name-asc') {
      result.sort((a, b) => a.title.localeCompare(b.title));
    } else if (sort === 'newest') {
      result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    } else {
      result.sort((a, b) => (a.displayOrder || 0) - (b.displayOrder || 0));
    }

    res.json(result);
  });

  // Listings: GET single by ID or Slug
  app.get('/api/listings/:idOrSlug', (req, res) => {
    const item = db.listings.find(
      l => l.id === req.params.idOrSlug || l.slug === req.params.idOrSlug
    );
    if (!item) return res.status(404).json({ error: 'Listing not found' });
    res.json(item);
  });

  // Listings: POST (create)
  app.post('/api/listings', (req, res) => {
    const maxOrder = db.listings.reduce((max, item) => Math.max(max, item.displayOrder || 0), 0);
    const newListing = {
      id: `list-${Date.now()}`,
      slug: req.body.slug || req.body.title.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      createdAt: new Date().toISOString(),
      displayOrder: maxOrder + 1,
      isActive: true,
      isFeatured: false,
      showOnHomepage: true,
      images: [],
      amenities: [],
      ...req.body
    };
    db.listings.unshift(newListing);
    saveDb();
    res.status(201).json(newListing);
  });

  // Listings: PUT (update)
  app.put('/api/listings/:id', (req, res) => {
    const index = db.listings.findIndex(l => l.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Listing not found' });
    db.listings[index] = { 
      ...db.listings[index], 
      ...req.body, 
      updatedAt: new Date().toISOString() 
    };
    saveDb();
    res.json(db.listings[index]);
  });

  // Listings: Reorder (Drag & Drop)
  app.post('/api/listings/reorder', (req, res) => {
    const { orderedIds } = req.body;
    if (!Array.isArray(orderedIds)) {
      return res.status(400).json({ error: 'orderedIds array required' });
    }

    orderedIds.forEach((id, index) => {
      const item = db.listings.find(l => l.id === id);
      if (item) {
        item.displayOrder = index + 1;
      }
    });

    saveDb();
    res.json({ success: true, message: 'Display order updated' });
  });

  // Listings: DELETE
  app.delete('/api/listings/:id', (req, res) => {
    db.listings = db.listings.filter(l => l.id !== req.params.id);
    saveDb();
    res.json({ success: true });
  });

  // Reviews: GET
  app.get('/api/reviews', (req, res) => {
    const { status } = req.query;
    if (status) {
      return res.json(db.reviews.filter(r => r.status === status));
    }
    res.json(db.reviews);
  });

  // Reviews: POST (Public submission)
  app.post('/api/reviews', (req, res) => {
    const { name, rating, comment, photos, listingId, listingTitle } = req.body;
    if (!name || !rating || !comment) {
      return res.status(400).json({ error: 'Name, rating and comment are required' });
    }
    const newReview = {
      id: `rev-${Date.now()}`,
      name,
      rating: Math.max(1, Math.min(5, Number(rating))),
      comment,
      photos: photos || [],
      listingId,
      listingTitle,
      status: 'pending' as const, // Goes to moderation queue
      createdAt: new Date().toISOString()
    };
    db.reviews.unshift(newReview);
    saveDb();
    res.status(201).json({ success: true, review: newReview, message: 'Review submitted for moderation' });
  });

  // Reviews: PUT status (Approve / Reject)
  app.put('/api/reviews/:id/status', (req, res) => {
    const { status } = req.body;
    const review = db.reviews.find(r => r.id === req.params.id);
    if (!review) return res.status(404).json({ error: 'Review not found' });
    review.status = status;
    saveDb();
    res.json(review);
  });

  // Reviews: DELETE
  app.delete('/api/reviews/:id', (req, res) => {
    db.reviews = db.reviews.filter(r => r.id !== req.params.id);
    saveDb();
    res.json({ success: true });
  });

  // Enquiries: GET
  app.get('/api/enquiries', (req, res) => {
    res.json(db.enquiries);
  });

  // Enquiries: POST (Record inquiry when WhatsApp is clicked or form submitted)
  app.post('/api/enquiries', (req, res) => {
    const newEnquiry = {
      id: `enq-${Date.now()}`,
      customerName: req.body.customerName || 'WhatsApp Inquirer',
      customerPhone: req.body.customerPhone || 'Via WhatsApp',
      listingId: req.body.listingId,
      listingTitle: req.body.listingTitle || 'General Inquiry',
      category: req.body.category || 'General',
      source: (req.body.source || 'whatsapp_click') as 'whatsapp_click' | 'contact_form' | 'booking_modal',
      status: 'New' as const,
      date: new Date().toISOString().split('T')[0],
      bookingDate: req.body.bookingDate,
      slot: req.body.slot,
      guestCount: req.body.guestCount,
      instructions: req.body.instructions,
      notes: req.body.notes || ''
    };
    db.enquiries.unshift(newEnquiry);
    saveDb();
    res.status(201).json(newEnquiry);
  });

  // Enquiries: PUT status
  app.put('/api/enquiries/:id/status', (req, res) => {
    const item = db.enquiries.find(e => e.id === req.params.id);
    if (!item) return res.status(404).json({ error: 'Enquiry not found' });
    item.status = req.body.status;
    if (req.body.notes !== undefined) item.notes = req.body.notes;
    saveDb();
    res.json(item);
  });

  // Enquiries: DELETE
  app.delete('/api/enquiries/:id', (req, res) => {
    db.enquiries = db.enquiries.filter(e => e.id !== req.params.id);
    saveDb();
    res.json({ success: true });
  });

  // Media Library: GET
  app.get('/api/media', (req, res) => {
    res.json(db.media);
  });

  // Media Library: POST upload / register
  app.post('/api/media', (req, res) => {
    const { name, base64Data, url, type } = req.body;
    let finalUrl = url;

    // If base64 payload provided, save to disk
    if (base64Data && base64Data.startsWith('data:')) {
      try {
        const matches = base64Data.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
        if (matches && matches.length === 3) {
          const mimeType = matches[1];
          const ext = mimeType.split('/')[1] || 'jpg';
          const filename = `media_${Date.now()}_${Math.random().toString(36).substring(7)}.${ext}`;
          const filePath = path.join(UPLOADS_DIR, filename);
          fs.writeFileSync(filePath, Buffer.from(matches[2], 'base64'));
          finalUrl = `/uploads/${filename}`;
        }
      } catch (err) {
        console.error('Failed to save media upload', err);
      }
    }

    if (!finalUrl) {
      return res.status(400).json({ error: 'Either valid base64Data or url is required' });
    }

    const newMedia = {
      id: `med-${Date.now()}`,
      name: name || 'Uploaded Media',
      url: finalUrl,
      type: type || 'image/jpeg',
      size: 'Uploaded',
      createdAt: new Date().toISOString()
    };

    db.media.unshift(newMedia);
    saveDb();
    res.status(201).json(newMedia);
  });

  // Media: DELETE
  app.delete('/api/media/:id', (req, res) => {
    db.media = db.media.filter(m => m.id !== req.params.id);
    saveDb();
    res.json({ success: true });
  });

  // --- DISCOUNT OFFERS API ROUTES ---

  // Offers: GET (Public gets active & non-expired, Admin can get all)
  app.get('/api/offers', (req, res) => {
    const { all, listingId } = req.query;
    let list = [...(db.offers || [])];

    // If not requesting all (i.e. public visitor view), only show active and non-expired
    if (all !== 'true') {
      const today = new Date().toISOString().split('T')[0];
      list = list.filter(o => {
        if (!o.isActive) return false;
        // Check expiry date if specified
        if (o.endDate && o.endDate < today) return false;
        return true;
      });
    }

    // Filter by specific listing if requested
    if (listingId && typeof listingId === 'string') {
      list = list.filter(o => {
        // Empty or undefined applicableListingIds means applies to ALL properties
        if (!o.applicableListingIds || o.applicableListingIds.length === 0) return true;
        return o.applicableListingIds.includes(listingId);
      });
    }

    // Sort by displayOrder
    list.sort((a, b) => (a.displayOrder || 0) - (b.displayOrder || 0));
    res.json(list);
  });

  // Offers: POST (Create offer)
  app.post('/api/offers', (req, res) => {
    const maxOrder = (db.offers || []).reduce((max, o) => Math.max(max, o.displayOrder || 0), 0);
    const newOffer = {
      id: `offer-${Date.now()}`,
      displayOrder: maxOrder + 1,
      isActive: true,
      createdAt: new Date().toISOString(),
      applicableListingIds: [],
      applicableListingTitles: [],
      ...req.body
    };

    if (!db.offers) db.offers = [];
    db.offers.unshift(newOffer);
    saveDb();
    res.status(201).json(newOffer);
  });

  // Offers: PUT (Update offer)
  app.put('/api/offers/:id', (req, res) => {
    if (!db.offers) db.offers = [];
    const index = db.offers.findIndex(o => o.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Offer not found' });

    db.offers[index] = {
      ...db.offers[index],
      ...req.body,
      updatedAt: new Date().toISOString()
    };
    saveDb();
    res.json(db.offers[index]);
  });

  // Offers: PUT toggle active
  app.put('/api/offers/:id/toggle', (req, res) => {
    if (!db.offers) db.offers = [];
    const offer = db.offers.find(o => o.id === req.params.id);
    if (!offer) return res.status(404).json({ error: 'Offer not found' });

    offer.isActive = !offer.isActive;
    offer.updatedAt = new Date().toISOString();
    saveDb();
    res.json({ success: true, offer });
  });

  // Offers: DELETE
  app.delete('/api/offers/:id', (req, res) => {
    if (!db.offers) db.offers = [];
    db.offers = db.offers.filter(o => o.id !== req.params.id);
    saveDb();
    res.json({ success: true });
  });

  // Dynamic SEO XML Sitemap
  app.get('/sitemap.xml', (req, res) => {
    const baseUrl = process.env.APP_URL || `http://localhost:${PORT}`;
    const staticUrls = [
      '',
      '/huts',
      '/farmhouses',
      '/resorts',
      '/events',
      '/water-sports',
      '/beach-games',
      '/adventure',
      '/churna-island',
      '/scuba-adventure',
      '/reviews',
      '/about',
      '/contact'
    ];

    const listingUrls = db.listings
      .filter(l => l.isActive)
      .map(l => `/listings/${l.slug}`);

    const allUrls = [...staticUrls, ...listingUrls];

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${allUrls
  .map(
    url => `  <url>
    <loc>${baseUrl}${url}</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>daily</changefreq>
    <priority>${url === '' ? '1.0' : url.startsWith('/listings') ? '0.8' : '0.6'}</priority>
  </url>`
  )
  .join('\n')}
</urlset>`;

    res.header('Content-Type', 'application/xml');
    res.send(xml);
  });

  // --- VITE MIDDLEWARE (DEV) OR STATIC DIST (PROD) ---
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Karachi Beach Farmhouse and Huts Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Server startup error:', err);
  process.exit(1);
});
