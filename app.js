const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const flash = require('connect-flash');

const app = express();

const multer = require('multer');

const upload = multer({
    dest: 'public/images'
});

// ================= DATABASE SETUP =================
const db = mysql.createConnection({
    host: 'c237-annie-mysql.mysql.database.azure.com',
    user: 'c237_025',
    password: 'c237025@2026!',
    database: 'c237_025_ca2team4',
    ssl: {
        rejectUnauthorized: false
    }
}).promise();

// ================= MIDDLEWARE SETUP =================
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Session Setup
app.use(session({
    secret: 'C237_secret_key',
    resave: false,
    saveUninitialized: false
}));

// Initialize Flash Messages
app.use(flash());

// Global Variables (Makes session user and flash messages available in all EJS files)
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

// ================= SECURITY GUARDS =================
function isLoggedIn(req, res, next) {
    if (!req.session.user) {
        req.flash('error_msg', 'Please log in to view that resource.');
        return res.redirect('/login');
    }
    next();
}

function isOwnerOrAdmin(req, res, next) {
    const targetId = parseInt(req.params.id);
    const currentUser = req.session.user;

    if (currentUser.student_id === targetId || currentUser.role === 'Admin') {
        return next();
    }
    req.flash('error_msg', 'Forbidden: You do not have permission to do that.');
    return res.redirect('/dashboard');
}

function isAdmin(req, res, next) {
    if (!req.session.user) {
        req.flash('error_msg', 'Please log in to view that resource.');
        return res.redirect('/login');
    }
    if (req.session.user.role !== 'Admin') {
        req.flash('error_msg', 'Forbidden: Admins only.');
        return res.redirect('/dashboard');
    }
    next();
}

// ================= ADEN - REGISTRATION =================

// 1. Root Route
app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/announcement');
    }
    res.redirect('/login');
});

// 2. Register Routes
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { full_name, email, password, school, role } = req.body;
    const finalRole = (role === 'Admin') ? 'Admin' : 'Student';

    try {
        const [existingUsers] = await db.execute('SELECT student_id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            req.flash('error_msg', 'Registration failed. Email already exists.');
            return res.redirect('/register');
        }

        await db.execute(
            'INSERT INTO users (full_name, email, password_hash, role, school) VALUES (?, ?, SHA1(?), ?, ?)',
            [full_name, email, password, finalRole, school]
        );

        req.flash('success_msg', 'You are now registered and can log in!');
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Registration failed. Please try again.');
        res.redirect('/register');
    }
});

// Login Routes
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find user by email
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            req.flash('error_msg', 'Invalid email or password.');
            return res.redirect('/login');
        }

        const user = rows[0];

        // Verify password
        const [matchRows] = await db.execute(
            'SELECT student_id FROM users WHERE email = ? AND password_hash = SHA1(?)',
            [email, password]
        );

        if (matchRows.length === 0) {
            req.flash('error_msg', 'Invalid email or password.');
            return res.redirect('/login');
        }

        // Store user information in session
        req.session.user = {
            student_id: user.student_id,
            full_name: user.full_name,
            email: user.email,
            role: user.role,
            school: user.school
        };

        req.flash('success_msg', 'Login successful!');

        // Redirect to announcements page
        return res.redirect('/announcement');

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'An error occurred during login.');
        return res.redirect('/login');
    }
});

// 4. Logout Route
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// 5. Dashboard Routes
app.get('/dashboard', isLoggedIn, (req, res) => {
    if (req.session.user.role === 'Admin') {
        return res.render('adminDashboard');
    }
    res.render('Dashboard');
});

// 6. View Profile
app.get('/viewProfile/:id', isLoggedIn, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT student_id, full_name, email, role, school, created_at FROM users WHERE student_id = ?',
            [req.params.id]
        );

        if (rows.length === 0) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/dashboard');
        }

        res.render('viewProfile', { profileUser: rows[0] });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server Error while fetching profile');
        res.redirect('/dashboard');
    }
});

// 7. Edit Profile Routes
app.get('/editProfile/:id', isLoggedIn, isOwnerOrAdmin, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT student_id, full_name, school FROM users WHERE student_id = ?', [req.params.id]);
        res.render('editProfile', { profileUser: rows[0] });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server Error loading edit form');
        res.redirect(`/viewProfile/${req.params.id}`);
    }
});

app.post('/editProfile/:id', isLoggedIn, isOwnerOrAdmin, async (req, res) => {
    const { full_name, school } = req.body;
    const targetId = req.params.id;

    try {
        await db.execute(
            'UPDATE users SET full_name = ?, school = ? WHERE student_id = ?',
            [full_name, school, targetId]
        );

        // Update active session data if user edits their own profile
        if (req.session.user.student_id === parseInt(targetId)) {
            req.session.user.full_name = full_name;
            req.session.user.school = school;
        }

        req.flash('success_msg', 'Profile updated successfully!');
        res.redirect(`/viewProfile/${targetId}`);
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Failed to update profile');
        res.redirect(`/editProfile/${targetId}`);
    }
});

// 8. Delete Profile Route
app.post('/deleteProfile/:id', isAdmin, async (req, res) => {
    const targetId = req.params.id;

    try {
        await db.execute('DELETE FROM users WHERE student_id = ?', [targetId]);

        // If self-deleted, log them out
        if (req.session.user.student_id === parseInt(targetId)) {
            return req.session.destroy(() => {
                res.redirect('/register');
            });
        }

        req.flash('success_msg', 'User account deleted successfully.');
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Failed to delete account');
        res.redirect(`/viewProfile/${targetId}`);
    }
});

// ================= Harinie - REGISTRATIONS =================

// Student registers for an event
app.post('/events/:id/register', isLoggedIn, async (req, res) => {
    const studentId = req.session.user.student_id;
    const eventId = req.params.id;

    try {
        const [existing] = await db.execute(
            `SELECT * FROM registrations
             WHERE student_id = ? AND event_id = ?`,
            [studentId, eventId]
        );

        if (existing.length > 0) {
            req.flash('error_msg', 'You have already registered for this event.');
            return res.redirect(`/events/${eventId}`);
        }

        await db.execute(
            `INSERT INTO registrations (student_id, event_id)
             VALUES (?, ?)`,
            [studentId, eventId]
        );

        req.flash('success_msg', 'Successfully registered!');
        res.redirect(`/events/${eventId}`);

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Registration failed.');
        res.redirect(`/events/${eventId}`);
    }
});

//registration page
app.get('/registration', isLoggedIn, async (req, res) => {

    try {

        const user = req.session.user;
        // admin view
        if (user.role === 'Admin') {

            const [registrations] = await db.execute(
                `SELECT r.registration_id, r.student_id, r.registered_at,
                        u.full_name, u.email,
                        e.title, e.event_date, e.location
                 FROM registrations r
                 JOIN users u ON r.student_id = u.student_id
                 JOIN events e ON r.event_id = e.event_id
                 ORDER BY r.registered_at DESC`
            );

            return res.render('manageRegistrations', { registrations });

        }
        // student view
        else {

            const [registrations] = await db.execute(
                `SELECT r.registration_id, r.registered_at,
                        e.title, e.category, e.location,
                        e.event_date, e.start_time, e.end_time
                 FROM registrations r
                 JOIN events e ON r.event_id = e.event_id
                 WHERE r.student_id = ?
                 ORDER BY e.event_date`,
                [user.student_id]
            );

            return res.render('registrations', { registrations });

        }

    } catch (err) {
        console.error(err);
        res.redirect('/dashboard');
    }

});



// Student views their registrations
// app.get('/registrations', isLoggedIn, async (req, res) => {
//     try {
//         const [registrations] = await db.execute(
//             `SELECT r.registration_id, r.registered_at,
//                     e.title, e.category, e.location,
//                     e.event_date, e.start_time, e.end_time
//              FROM registrations r
//              JOIN events e ON r.event_id = e.event_id
//              WHERE r.student_id = ?
//              ORDER BY e.event_date`,
//             [req.session.user.student_id]
//         );

//         res.render('registrations', { registrations });

//     } catch (err) {
//         console.error(err);
//         res.redirect('/dashboard');
//     }
// });


// Student cancels their registration
app.post('/registrations/:id/delete', isLoggedIn, async (req, res) => {
    try {
        await db.execute(
            `DELETE FROM registrations
             WHERE registration_id = ? AND student_id = ?`,
            [req.params.id, req.session.user.student_id]
        );

        req.flash('success_msg', 'Registration cancelled successfully.');
        res.redirect('/registrations');

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Unable to cancel registration.');
        res.redirect('/registrations');
    }
});


// Admin views all registrations
// app.get('/admin/registrations', isLoggedIn, isAdmin, async (req, res) => {
//     try {
//         const [registrations] = await db.execute(
//             `SELECT r.registration_id, r.student_id, r.registered_at,
//                     u.full_name, u.email,
//                     e.title, e.event_date, e.location
//              FROM registrations r
//              JOIN users u ON r.student_id = u.student_id
//              JOIN events e ON r.event_id = e.event_id
//              ORDER BY r.registered_at DESC`
//         );

//         res.render('manageRegistrations', { registrations });

//     } catch (err) {
//         console.error(err);
//         res.redirect('/admin');
//     }
// });


// Admin removes a student registration
app.post('/admin/registrations/:id/delete',
    isLoggedIn,
    isAdmin,
    async (req, res) => {
        try {
            await db.execute(
                `DELETE FROM registrations
                 WHERE registration_id = ?`,
                [req.params.id]
            );

            req.flash('success_msg', 'Student removed successfully.');
            res.redirect('/admin/registrations');

        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Unable to remove student.');
            res.redirect('/admin/registrations');
        }
    }
);

//============= YuYi - Announcement ====================
app.get('/announcement', isLoggedIn, async (req, res) => {
    try {
        const [results] = await db.query(
            'SELECT * FROM events WHERE announcement = 1'
        );

        let announcements = results;
        const filter = req.query.filter;

        if (filter) {
            announcements = announcements.filter(
                announcement => announcement.category === filter
            );
        }

        res.render('announcement', {
            message: announcements,
            user: req.session.user
        });
    } catch (err) {
        console.error(err);
        res.send("Database error");
    }
});

app.get('/updateAnnouncement/:id', isLoggedIn, isAdmin, async (req, res) => {
    const id = req.params.id;

    try {
        const [results] = await db.query(
            'SELECT * FROM events WHERE event_id = ?',
            [id]
        );

        if (results.length > 0) {
            res.render('updateAnnouncement', {
                message: results[0],
                id: id
            });
        } else {
            res.redirect('/announcement');
        }
    } catch (err) {
        console.error(err);
        res.redirect('/announcement');
    }
});

app.post('/updateAnnouncement/:id', isLoggedIn, isAdmin, upload.single('image'), async (req, res) => {
    const id = req.params.id;
    const { title, category, details } = req.body;
    let image;
    if (req.file) {
        image = req.file.filename;
    } else {
        const [result] = await db.query(
            'SELECT image FROM events WHERE event_id = ?',
            [id]
        );

        image = result[0].image;
    }

    await db.query('UPDATE events SET image = ?,title = ?, category = ?, description = ? WHERE event_id = ?', [image, title, category, details, id]

    );

    res.redirect(`/detailAnnouncement/${id}`); // Redirect back to the announcement page
});


app.get('/detailAnnouncement/:id', isLoggedIn, async (req, res) => {
    const id = req.params.id;

    try {
        const [results] = await db.query(
            'SELECT * FROM events WHERE event_id = ?',
            [id]
        );

        if (results.length > 0) {
            res.render('detailAnnouncement', {
                message: results[0],
                id: id
            });
        } else {
            res.redirect('/announcement');
        }
    } catch (err) {
        console.error(err);
        res.redirect('/announcement');
    }
});

// Display add announcement page
app.get('/addAnnouncement', isLoggedIn, isAdmin, async (req, res) => {

    try {
        const [results] = await db.query(
            'SELECT event_id, title FROM events WHERE announcement = 0'
        );

        res.render('addAnnouncement', { events: results });

    } catch (error) {
        console.error(error);
        res.send("Database error");
    }

});


// Add announcement
app.post('/addAnnouncement', isLoggedIn, isAdmin, async (req, res) => {

    const { eventId } = req.body;

    try {

        await db.query(
            'UPDATE events SET announcement = 1 WHERE event_id = ?',
            [eventId]
        );

        res.redirect('/announcement');

    } catch (error) {
        console.error(error);
        res.send("Database error");
    }

});


app.get('/deleteAnnouncement/:id', isLoggedIn, isAdmin, async (req, res) => {
    const id = req.params.id;

    try {
        await db.query(
            'UPDATE events SET announcement = 0 WHERE event_id = ?',
            [id]
        );

        res.redirect('/announcement');
    } catch (error) {
        console.error(error);
        res.send("Database error");
    }
}
);

//============= Isaac - Certificate/ Attendance =========================
// GET: Main Dashboard (Admin Roster vs Student Events)
app.get('/attendance', isLoggedIn, async (req, res) => {
    const user = req.session.user;

    if (user.role === 'Admin') {
        // ADMIN: Retrieve all registrations across all students & events
        const sql = `
            SELECT r.registration_id, r.status, r.checkin_time, 
                   u.student_id, u.full_name AS student_name, e.title 
            FROM registrations r
            JOIN users u ON r.student_id = u.student_id
            JOIN events e ON r.event_id = e.event_id
        `;
        db.query(sql, (err, results) => {
            if (err) throw err;
            res.render('index', { attendanceList: results });
        });
    } else {
        // STUDENT: Retrieve ONLY their registered events
        const sql = `
            SELECT r.registration_id, r.status, r.checkin_time, e.title 
            FROM registrations r
            JOIN events e ON r.event_id = e.event_id
            WHERE r.student_id = ?
        `;
        db.query(sql, [user.student_id], (err, results) => {
            if (err) throw err;
            res.render('index', { attendanceList: results });
        });
    }
});

// POST: Admin marks student attendance as Present or Absent
app.post('/admin/mark-attendance', isAdmin, (req, res) => {
    const { registration_id, status } = req.body;
    const checkinTime = (status === 'Present') ? new Date() : null;

    const sql = `UPDATE registrations SET status = ?, checkin_time = ? WHERE registration_id = ?`;
    db.query(sql, [status, checkinTime, registration_id], (err) => {
        if (err) req.flash('error', 'Could not update status.');
        else req.flash('success', 'Attendance status updated.');
        res.redirect('/');
    });
});

// GET: Render Certificate
app.get('/certificate/:registration_id', isLoggedIn, (req, res) => {
    const { registration_id } = req.params;
    const user = req.session.user;

    const sql = `
    SELECT r.registration_id, r.status, r.student_id, 
           u.full_name AS student_name, e.event_name, e.event_date 
    FROM registrations r
    JOIN users u ON r.student_id = u.user_id
    JOIN events e ON r.event_id = e.event_id
    WHERE r.registration_id = ?
`;

    db.query(sql, [registration_id], (err, results) => {
        if (err || results.length === 0) {
            req.flash('error', 'Certificate record not found.');
            return res.redirect('/');
        }

        const cert = results[0];

        // Security Check 1: Attendance must be 'Present'
        if (cert.status !== 'Present') {
            req.flash('error', 'Certificate unavailable: You have not attended this event.');
            return res.redirect('/');
        }

        // Security Check 2: Student can only access their own certificate
        if (user.role !== 'Admin' && cert.student_id !== user.student_id) {
            req.flash('error', 'Access denied: You cannot view another student\'s certificate.');
            return res.redirect('/');
        }

        res.render('certificate', { cert });
    });
});
// ================= hnin san- EVENT MANAGEMENT ROUTES =================

// List / Search / Filter Events
app.get('/events', isLoggedIn, async (req, res) => {
    const { keyword, category, date } = req.query;

    let sql = 'SELECT * FROM events WHERE 1=1';
    const params = [];

    if (keyword) {
        sql += ' AND (title LIKE ? OR description LIKE ? OR location LIKE ?)';
        const like = `%${keyword}%`;
        params.push(like, like, like);
    }

    if (category) {
        sql += ' AND category = ?';
        params.push(category);
    }

    if (date) {
        sql += ' AND event_date = ?';
        params.push(date);
    }

    sql += ' ORDER BY event_date ASC, start_time ASC';

    try {
        const [events] = await db.execute(sql, params);

        const [categoryRows] = await db.execute(
            `SELECT DISTINCT category
             FROM events
             WHERE category IS NOT NULL
             ORDER BY category`
        );

        res.render('eventsList', {
            events,
            categories: categoryRows.map(row => row.category),
            filters: {
                keyword: keyword || '',
                category: category || '',
                date: date || ''
            }
        });

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Failed to load events.');
        res.redirect('/dashboard');
    }
});


// CREATE EVENT: Show form
app.get('/events/new', isLoggedIn, isAdmin, (req, res) => {
    res.render('eventForm', {
        event: null,
        formAction: '/events/new'
    });
});


// CREATE EVENT: Handle form submission
app.post('/events/new', isLoggedIn, isAdmin, async (req, res) => {
    const {
        title,
        description,
        category,
        location,
        event_date,
        start_time,
        end_time,
        capacity
    } = req.body;

    try {
        await db.execute(
            `INSERT INTO events (
                title,
                description,
                category,
                location,
                event_date,
                start_time,
                end_time,
                capacity,
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                title,
                description,
                category,
                location,
                event_date,
                start_time,
                end_time,
                capacity,
                req.session.user.student_id
            ]
        );

        req.flash('success_msg', 'Event created successfully!');
        res.redirect('/events');

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Failed to create event.');
        res.redirect('/events/new');
    }
});


// READ EVENT: View event details with activities
app.get('/events/:id', isLoggedIn, async (req, res) => {
    const eventId = req.params.id;

    try {
        const [events] = await db.execute(
            'SELECT * FROM events WHERE event_id = ?',
            [eventId]
        );

        if (events.length === 0) {
            req.flash('error_msg', 'Event not found.');
            return res.redirect('/events');
        }

        const [activities] = await db.execute(
    `SELECT *
     FROM activities
     WHERE event_id = ?
     ORDER BY start_time ASC`,
    [eventId]
);

        res.render('eventdetails', {
            event: events[0],
            activities
        });

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server error while fetching event.');
        res.redirect('/events');
    }
});


// UPDATE EVENT: Show edit form
app.get('/events/:id/edit', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const [events] = await db.execute(
            'SELECT * FROM events WHERE event_id = ?',
            [req.params.id]
        );

        if (events.length === 0) {
            req.flash('error_msg', 'Event not found.');
            return res.redirect('/events');
        }

        res.render('eventForm', {
            event: events[0],
            formAction: `/events/${req.params.id}/edit`
        });

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server error loading edit form.');
        res.redirect('/events');
    }
});


// UPDATE EVENT: Save changes
app.post('/events/:id/edit', isLoggedIn, isAdmin, async (req, res) => {
    const eventId = req.params.id;

    const {
        title,
        description,
        category,
        location,
        event_date,
        start_time,
        end_time,
        capacity
    } = req.body;

    try {
        await db.execute(
            `UPDATE events
             SET title = ?,
                 description = ?,
                 category = ?,
                 location = ?,
                 event_date = ?,
                 start_time = ?,
                 end_time = ?,
                 capacity = ?
             WHERE event_id = ?`,
            [
                title,
                description,
                category,
                location,
                event_date,
                start_time,
                end_time,
                capacity,
                eventId
            ]
        );

        req.flash('success_msg', 'Event updated successfully!');
        res.redirect(`/events/${eventId}`);

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Failed to update event.');
        res.redirect(`/events/${eventId}/edit`);
    }
});


// DELETE EVENT
app.post('/events/:id/delete', isLoggedIn, isAdmin, async (req, res) => {
    const eventId = req.params.id;

    try {
        await db.execute(
            'DELETE FROM events WHERE event_id = ?',
            [eventId]
        );

        req.flash('success_msg', 'Event deleted successfully.');
        res.redirect('/events');

    } catch (err) {
        console.error(err);
        req.flash(
            'error_msg',
            'Failed to delete event. It may have existing registrations.'
        );
        res.redirect(`/events/${eventId}`);
    }
});


// ================= Jayden - ACTIVITY MANAGEMENT ROUTES =================

// CREATE ACTIVITY: Show form
app.get(
    '/events/:eventId/activities/new',
    isLoggedIn,
    isAdmin,
    async (req, res) => {
        const eventId = req.params.eventId;

        try {
            const [events] = await db.execute(
                'SELECT * FROM events WHERE event_id = ?',
                [eventId]
            );

            if (events.length === 0) {
                req.flash('error_msg', 'Event not found.');
                return res.redirect('/events');
            }

            res.render('activityForm', {
                event: events[0],
                activity: null,
                formAction: `/events/${eventId}/activities/new`
            });

        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Failed to load activity form.');
            res.redirect(`/events/${eventId}`);
        }
    }
);


// CREATE ACTIVITY: Save new activity
app.post(
    '/events/:eventId/activities/new',
    isLoggedIn,
    isAdmin,
    async (req, res) => {
        const eventId = req.params.eventId;

        const {
            activity_name,
            activity_description,
            activity_date,
            start_time,
            end_time,
            activity_location,
            activity_category
        } = req.body;

        try {
            await db.execute(
                `INSERT INTO activities (
                    event_id,
                    activity_name,
                    activity_description,
                    activity_date,
                    start_time,
                    end_time,
                    activity_location,
                    activity_category
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    eventId,
                    activity_name,
                    activity_description,
                    activity_date,
                    start_time,
                    end_time,
                    activity_location,
                    activity_category
                ]
            );

            req.flash('success_msg', 'Activity added successfully!');
            res.redirect(`/events/${eventId}`);

        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Failed to add activity.');
            res.redirect(`/events/${eventId}/activities/new`);
        }
    }
);


// UPDATE ACTIVITY: Show edit form
app.get(
    '/activities/:id/edit',
    isLoggedIn,
    isAdmin,
    async (req, res) => {
        const activityId = req.params.id;

        try {
            const [activities] = await db.execute(
                'SELECT * FROM activities WHERE activity_id = ?',
                [activityId]
            );

            if (activities.length === 0) {
                req.flash('error_msg', 'Activity not found.');
                return res.redirect('/events');
            }

            const activity = activities[0];

            const [events] = await db.execute(
                'SELECT * FROM events WHERE event_id = ?',
                [activity.event_id]
            );

            if (events.length === 0) {
                req.flash('error_msg', 'Linked event not found.');
                return res.redirect('/events');
            }

            res.render('activityForm', {
                event: events[0],
                activity,
                formAction: `/activities/${activityId}/edit`
            });

        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Failed to load activity.');
            res.redirect('/events');
        }
    }
);


// UPDATE ACTIVITY: Save changes
app.post(
    '/activities/:id/edit',
    isLoggedIn,
    isAdmin,
    async (req, res) => {
        const activityId = req.params.id;

        const {
            activity_name,
            activity_description,
            activity_date,
            start_time,
            end_time,
            activity_location,
            activity_category
        } = req.body;

        try {
            const [activities] = await db.execute(
                'SELECT event_id FROM activities WHERE activity_id = ?',
                [activityId]
            );

            if (activities.length === 0) {
                req.flash('error_msg', 'Activity not found.');
                return res.redirect('/events');
            }

            const eventId = activities[0].event_id;

            await db.execute(
                `UPDATE activities
                 SET activity_name = ?,
                     activity_description = ?,
                     activity_date = ?,
                     start_time = ?,
                     end_time = ?,
                     activity_location = ?,
                     activity_category = ?
                 WHERE activity_id = ?`,
                [
                    activity_name,
                    activity_description,
                    activity_date,
                    start_time,
                    end_time,
                    activity_location,
                    activity_category,
                    activityId
                ]
            );

            req.flash('success_msg', 'Activity updated successfully!');
            res.redirect(`/events/${eventId}`);

        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Failed to update activity.');
            res.redirect(`/activities/${activityId}/edit`);
        }
    }
);


// DELETE ACTIVITY
app.post(
    '/activities/:id/delete',
    isLoggedIn,
    isAdmin,
    async (req, res) => {
        const activityId = req.params.id;

        try {
            const [activities] = await db.execute(
                'SELECT event_id FROM activities WHERE activity_id = ?',
                [activityId]
            );

            if (activities.length === 0) {
                req.flash('error_msg', 'Activity not found.');
                return res.redirect('/events');
            }

            const eventId = activities[0].event_id;

            await db.execute(
                'DELETE FROM activities WHERE activity_id = ?',
                [activityId]
            );

            req.flash('success_msg', 'Activity deleted successfully!');
            res.redirect(`/events/${eventId}`);

        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Failed to delete activity.');
            res.redirect('/events');
        }
    }
);
// ================= START SERVER =================
app.listen(3001, () => {
    console.log('Server running on http://localhost:3001');
});

