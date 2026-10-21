# Seminar Information Bot

**An AI-Powered Seminar Discovery, Management, and Academic Assistant Platform for Colleges and Universities.**

Built with React 19, TypeScript, Express, Vite, and the `@google/genai` TypeScript SDK (powered by `gemini-3.8-flash`).

---

## 1. Project Overview

**Seminar Information Bot** is a centralized, production-grade web application tailored for higher education institutions. It connects students, faculty organizers, academic administrators, and invited industry speakers through a unified platform to discover upcoming academic seminars, masterclasses, and workshops, reserve real seats, issue verifiable digital passes with calendar synchronization (`.ics`), and answer questions via an AI Assistant grounded strictly in verified college event records.

---

## 2. Key Features

### 🎓 Home Dashboard & Verified Metrics
- **Real-Time Database Statistics**: Live tracking of Upcoming Seminars, Available Registrations, My Registered Seminars, and Completed Seminars. (Zero fake statistics).
- **Featured Masterclasses & Popular Topics**: Categorized across Artificial Intelligence, Cybersecurity, Web Development, Cloud Computing, IoT, Entrepreneurship, and Career Placement.
- **Official Campus Announcements**: High-priority broadcasts pinned to the dashboard.

### 🔍 Interactive Seminar Discovery & Filtering
- **Multi-Factor Search**: Search by title, keynote speaker name, keywords, and topics.
- **Dynamic Filters**: Filter by category, format (*In-Person*, *Online*, *Hybrid*), difficulty level (*Beginner*, *Intermediate*, *Advanced*), and open seat availability.
- **Smart Sorting**: Sort by upcoming event date, registration count, or available seat count.

### 📋 Comprehensive Seminar Detail Modal
- In-depth syllabus breakdown, learning objectives, timetable agenda with timestamps, speaker biographical dossiers with LinkedIn links, eligibility, prerequisites, and live seat meters.

### 🎟️ Real Registration System & Digital Ticket Generator
- **Capacity & Duplicate Protection**: Strictly prevents duplicate registrations per participant email and enforces seating limits and registration deadlines.
- **Digital University Pass**: Generates unique ticket codes (e.g., `PASS-ART-8491`), visual QR badge, and attendee information.
- **Calendar Integration**: One-click download of dynamic iCalendar (`.ics`) files compatible with Google Calendar, Apple Calendar, and Outlook.
- **Self-Service Cancellation**: Allows attendees to cancel registrations and automatically restores available seats for other students.

### 🤖 AI Seminar Assistant (Server-Side Gemini 3.8 Flash)
- **Strict Database Grounding**: The AI assistant uses the server's verified seminar database snapshot as ground truth. It will never invent fake seminars, dates, or speakers.
- **Multilingual Support**: Supports English, Hindi (हिन्दी), and Marathi (मराठी).
- **Concept Explanations**: Explains computer science and engineering topics (e.g. Cloud Computing, Zero Trust, RAG, Web Performance) in simple, student-friendly language.
- **Embedded Seminar Cards**: When the bot mentions a seminar, clickable interactive cards appear in the conversation stream with direct "View Details" and "Register" buttons.
- **Interactive Suggestions**: Dynamic follow-up question pills, response copying, and session clear.

### 🏢 Faculty & Organizer Portal
- **Create & Edit Seminars**: Full seminar authoring form including agenda, speaker profile, venue, and capacity limits.
- **Publish & Unpublish**: Easily toggle between draft and published statuses.
- **Event Cancellation**: Cancel events with mandatory reasons, automatically notifying registered attendees and cancelling their reservations.
- **Attendee Management & CSV Export**: Inspect participant rosters and export attendee lists as standard CSV spreadsheets.

### 🏛️ University Administrator Desk
- **Campus Metrics**: Aggregated counts across published seminars, registrations, and archive history.
- **Campus Broadcast Announcements**: Create high-priority announcements pushed to all student notification feeds.
- **Audit & Verification Queue**: Real-time monitoring of all university events.

### 🔔 In-App Notification Center
- Real-time notification bell with unread counters, registration confirmations, schedule reminders, and cancellation alerts.

### 🌓 Accessibility & Dark Mode
- Dark and light theme toggle with persistent user preference in `localStorage`.

---

## 3. Technology Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS, Lucide React, Motion.
- **Backend**: Node.js, Express, `server.ts` with `vite.middlewares` mounted in development.
- **AI Engine**: `@google/genai` TypeScript SDK using `gemini-3.8-flash`.
- **Database**: Local JSON storage (`data/db.json`) with ACID-like consistency, thread-safe updates, and initial collegiate dataset.
- **Calendar**: RFC 5545 iCalendar (`.ics`) dynamically generated on the server.

---

## 4. Environment Variables

Define the following environment variables in your environment or `.env` file (see `.env.example`):

```bash
# GEMINI_API_KEY: Injected by AI Studio runtime secrets
GEMINI_API_KEY="YOUR_GEMINI_API_KEY"

# PORT: Server port (defaults to 3000)
PORT=3000

# APP_URL: URL where the application is hosted
APP_URL="http://localhost:3000"
```

---

## 5. Development & Build Commands

### Install Dependencies
```bash
npm install
```

### Run Full-Stack Development Server
```bash
npm run dev
```
Starts Express on port 3000 with Vite middleware handling client-side assets and hot reloading.

### Compile & Typecheck
```bash
npm run lint
```

### Build for Production
```bash
npm run build
```

### Start Production Server
```bash
npm start
```

---

## 6. Testing Instructions

1. **Discover Seminars**: Go to **Explore Seminars** and test filters by category (*Artificial Intelligence*, *Cybersecurity*), format (*Online*, *In-Person*), and search query (*LLM*, *Zero Trust*).
2. **Register**: Click "Register" on any seminar. Enter your participant details and submit. View the generated digital ticket with your unique Ticket Code.
3. **Calendar**: Click "Add to Calendar (.ics)" on the ticket to download the calendar event file.
4. **My Registrations**: Open **My Registrations** to view your active passes, test cancelling a registration, and notice the seat count dynamically restore.
5. **AI Assistant**: Open **AI Assistant** and ask:
   - *"What seminars are available this week?"*
   - *"Explain cloud computing in simple language"*
   - *"Which seminars are suitable for beginners?"*
   - Switch language to हिन्दी or मराठी and test response.
6. **Organizer Features**: In the top navigation role switcher, select **Faculty Organizer**. Go to **Organizer Portal** to create a seminar, edit details, or export the attendee CSV.
7. **Administrator Features**: In the role switcher, select **College Administrator**. Go to **Admin Desk** to post a campus announcement and inspect global metrics.

---

## 7. Known Limitations

- Real push notifications or external SMTP email sending requires third-party SMTP/Twilio credentials; the in-app notification center provides real-time in-app alerts and notifications.
- Database records are persisted to `data/db.json` on the server filesystem. For enterprise multi-region deployments, migration to PostgreSQL via Cloud SQL or Firestore can be added seamlessly.
