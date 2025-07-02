const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const twilio = require('twilio');

dotenv.config();

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// Set up SQLite database
const dbPath = path.resolve(__dirname, 'donkeydrop.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Create users table (id, name, email, password)
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT,
  phone TEXT
)`);

// Add isOnline column to users table if it doesn't exist
// (This will error if the column exists, but that's fine)
db.run('ALTER TABLE users ADD COLUMN isOnline INTEGER DEFAULT 0', (err) => {
  // Ignore error if column already exists
});

// Create time_slots table (id, flyerId, startTime, endTime, pickupLocation)
db.run(`CREATE TABLE IF NOT EXISTS time_slots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  flyerId INTEGER NOT NULL,
  startTime TEXT NOT NULL,
  endTime TEXT NOT NULL,
  pickupLocation TEXT NOT NULL,
  FOREIGN KEY(flyerId) REFERENCES users(id)
)`);

// Create delivery_requests table
db.run(`CREATE TABLE IF NOT EXISTS delivery_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  buyerId INTEGER NOT NULL,
  flyerId INTEGER,
  flyerSlotId INTEGER,
  eta TEXT NOT NULL,
  orderType TEXT NOT NULL,
  deliveryLocation TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  pickupLocation TEXT,
  startTime TEXT,
  endTime TEXT,
  FOREIGN KEY(buyerId) REFERENCES users(id),
  FOREIGN KEY(flyerId) REFERENCES users(id),
  FOREIGN KEY(flyerSlotId) REFERENCES time_slots(id) ON DELETE SET NULL
)`);

// Log users table columns at startup for debugging
try {
  db.all('PRAGMA table_info(users)', (err, columns) => {
    if (err) {
      console.error('Error fetching users table info:', err);
    } else {
      console.log('Users table columns:', columns.map(col => col.name));
    }
  });
} catch (e) {
  console.error('Exception during PRAGMA table_info:', e);
}

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

app.get('/', (req, res) => {
  res.send('DonkeyDrop backend is running!');
});

app.post('/signup', async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password || !phone) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)',
    [name, email, hashedPassword, phone],
    function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          // This can be triggered by UNIQUE constraint on email
          return res.status(409).json({ error: 'Email already registered' });
        }
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ id: this.lastID, name, email, phone });
    }
  );
});

app.post('/flyer/slot', (req, res) => {
  const { flyerId, startTime, endTime, pickupLocation } = req.body;
  if (!flyerId || !startTime || !endTime || !pickupLocation) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  db.run(
    'INSERT INTO time_slots (flyerId, startTime, endTime, pickupLocation) VALUES (?, ?, ?, ?)',
    [flyerId, startTime, endTime, pickupLocation],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ id: this.lastID, flyerId, startTime, endTime, pickupLocation });
    }
  );
});

app.get('/flyer/slots', (req, res) => {
  const { pickupLocation } = req.query;
  const now = new Date().toISOString();

  let query = `
    SELECT time_slots.id, flyerId, startTime, endTime, pickupLocation, users.name as flyerName, users.email as flyerEmail
    FROM time_slots
    JOIN users ON time_slots.flyerId = users.id
    WHERE time_slots.endTime > ?
  `;
  const params = [now];

  if (pickupLocation) {
    query += ` AND time_slots.pickupLocation = ?`;
    params.push(pickupLocation);
  }

  query += ` ORDER BY startTime`;

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.get('/flyer/:flyerId/slots', (req, res) => {
  const { flyerId } = req.params;
  const now = new Date().toISOString();

  const query = `
    SELECT ts.id, ts.startTime, ts.endTime, ts.pickupLocation
    FROM time_slots ts
    WHERE ts.flyerId = ?
      AND (
        ts.endTime > ?
        OR ts.id IN (
          SELECT flyerSlotId FROM delivery_requests WHERE flyerId = ? AND status = 'pending'
        )
      )
    ORDER BY ts.startTime
  `;

  db.all(query, [flyerId, now, flyerId], (err, rows) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/buyer/request', (req, res) => {
  const { buyerId, eta, orderType, deliveryLocation, pickupLocation } = req.body;
  if (!buyerId || !eta || !orderType || !deliveryLocation || !pickupLocation) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const query = `
    INSERT INTO delivery_requests 
      (buyerId, flyerId, flyerSlotId, eta, orderType, deliveryLocation, startTime, endTime, pickupLocation) 
    VALUES (?, NULL, NULL, ?, ?, ?, NULL, NULL, ?)
  `;
  const params = [buyerId, eta, orderType, deliveryLocation, pickupLocation];

  db.run(query, params, function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error creating request' });
    }
    res.status(201).json({ id: this.lastID });
  });
});

app.get('/flyer/tasks/:flyerId', (req, res) => {
  const { flyerId } = req.params;
  const query = `
    SELECT 
      dr.id as requestId, 
      dr.flyerSlotId, 
      dr.eta, 
      dr.orderType, 
      dr.deliveryLocation, 
      dr.status,
      dr.startTime, 
      dr.endTime, 
      dr.pickupLocation,
      u.name as buyerName, 
      u.email as buyerEmail
    FROM delivery_requests dr
    JOIN users u ON dr.buyerId = u.id
    WHERE dr.flyerId = ?
    ORDER BY dr.eta
  `;
  db.all(query, [flyerId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.get('/buyer/tasks/:buyerId', (req, res) => {
  const { buyerId } = req.params;
  const now = new Date().toISOString();
  const query = `
    SELECT 
      dr.id as requestId, 
      dr.eta, 
      dr.orderType, 
      dr.deliveryLocation, 
      dr.status,
      dr.startTime, 
      dr.endTime, 
      dr.pickupLocation,
      u.name as flyerName
    FROM delivery_requests dr
    LEFT JOIN users u ON dr.flyerId = u.id
    WHERE dr.buyerId = ? AND dr.status = 'pending' AND (
      (dr.flyerId IS NULL AND dr.eta > ?)
      OR (dr.flyerId IS NOT NULL)
    )
    ORDER BY dr.eta
  `;
  db.all(query, [buyerId, now], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.patch('/delivery/:id/complete', (req, res) => {
  const requestId = req.params.id;
  db.run(
    'UPDATE delivery_requests SET status = ? WHERE id = ?',
    ['completed', requestId],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Request not found' });
      }
      res.json({ success: true });
    }
  );
});

app.delete('/delivery/:requestId', (req, res) => {
  const { requestId } = req.params;
  db.run('DELETE FROM delivery_requests WHERE id = ?', [requestId], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    res.json({ success: true, message: 'Delivery record deleted.' });
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    // Don't send password back
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  });
});

app.delete('/flyer/slot/:slotId', (req, res) => {
    const { slotId } = req.params;

    // First, check if any PENDING delivery requests are associated with this slot
    const checkQuery = `SELECT id FROM delivery_requests WHERE flyerSlotId = ? AND status = 'pending'`;
    db.get(checkQuery, [slotId], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error while checking requests.' });
        }
        if (row) {
            return res.status(409).json({ error: 'Cannot remove a slot that is already booked by a buyer.' });
        }

        // If no requests, proceed with deletion
        const deleteQuery = `DELETE FROM time_slots WHERE id = ?`;
        db.run(deleteQuery, [slotId], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Database error while deleting slot.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Slot not found.' });
            }
            res.status(200).json({ success: true, message: 'Slot removed successfully.' });
        });
    });
});

app.delete('/buyer/request/:requestId', (req, res) => {
  const { requestId } = req.params;
  db.run(
    'UPDATE delivery_requests SET status = ? WHERE id = ? AND status = "pending"',
    ['cancelled', requestId],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Pending request not found or already processed' });
      }
      res.json({ success: true, message: 'Order cancelled.' });
    }
  );
});

// Endpoint to set flyer online/offline
app.post('/flyer/:flyerId/online', (req, res) => {
  const { flyerId } = req.params;
  const { isOnline } = req.body;
  console.log(`Setting flyer ${flyerId} online status to:`, isOnline);
  db.run('UPDATE users SET isOnline = ? WHERE id = ?', [isOnline ? 1 : 0, flyerId], function (err) {
    if (err) {
      console.error('Error updating isOnline for flyer:', flyerId, err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    if (this.changes === 0) {
      console.warn('No flyer found with id:', flyerId);
      return res.status(404).json({ error: 'Flyer not found' });
    }
    res.json({ success: true, isOnline: !!isOnline });
  });
});

// Endpoint to get all online flyers
app.get('/flyers/online', (req, res) => {
  db.all('SELECT id, name, email FROM users WHERE isOnline = 1', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// Get all unassigned, pending orders
app.get('/orders/unassigned', (req, res) => {
  const now = new Date().toISOString();
  db.all(
    `SELECT dr.id as requestId, dr.buyerId, dr.eta, dr.orderType, dr.deliveryLocation, dr.status, dr.pickupLocation, u.name as buyerName, u.email as buyerEmail
     FROM delivery_requests dr
     JOIN users u ON dr.buyerId = u.id
     WHERE dr.flyerId IS NULL AND dr.status = 'pending' AND dr.eta > ?
     ORDER BY dr.eta`,
    [now],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// Flyer claims an order
app.post('/orders/:orderId/claim', (req, res) => {
  const { orderId } = req.params;
  const { flyerId } = req.body;
  if (!flyerId) return res.status(400).json({ error: 'Missing flyerId' });
  db.run(
    'UPDATE delivery_requests SET flyerId = ? WHERE id = ? AND flyerId IS NULL AND status = "pending"',
    [flyerId, orderId],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (this.changes === 0) return res.status(404).json({ error: 'Order not found or already claimed' });
      // Fetch buyer's phone number and name
      db.get(
        `SELECT u.phone, u.name, dr.orderType FROM delivery_requests dr JOIN users u ON dr.buyerId = u.id WHERE dr.id = ?`,
        [orderId],
        (err, row) => {
          if (!err && row && row.phone) {
            twilioClient.messages.create({
              body: `Hi ${row.name}, your order (${row.orderType}) has been claimed by a donkey and is on its way!`,
              from: process.env.TWILIO_PHONE_NUMBER,
              to: row.phone
            }).then(message => {
              console.log('SMS sent:', message.sid);
            }).catch(e => {
              console.error('SMS error:', e);
            });
          }
        }
      );
      res.json({ success: true });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
}); 