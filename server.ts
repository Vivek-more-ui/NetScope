import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { db } from './src/server/db.js';
import { askSeminarBot } from './src/server/gemini.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = parseInt(process.env.PORT || '3000', 10);

  app.use(express.json());

  // 1. Seminars API
  app.get('/api/seminars', (req: Request, res: Response) => {
    try {
      const { category, level, format, status, search } = req.query;
      const seminars = db.getSeminars({
        category: category as string,
        level: level as string,
        format: format as string,
        status: status as string,
        search: search as string,
      });
      res.json({ success: true, data: seminars });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/seminars/:id', (req: Request, res: Response) => {
    try {
      const seminar = db.getSeminarById(req.params.id);
      if (!seminar) {
        res.status(404).json({ success: false, error: 'Seminar not found' });
        return;
      }
      res.json({ success: true, data: seminar });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/seminars', (req: Request, res: Response) => {
    try {
      const seminarData = req.body;
      if (!seminarData.title || !seminarData.category || !seminarData.date) {
        res.status(400).json({ success: false, error: 'Missing required seminar fields (title, category, date)' });
        return;
      }
      const created = db.createSeminar(seminarData);
      res.status(201).json({ success: true, data: created });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.put('/api/seminars/:id', (req: Request, res: Response) => {
    try {
      const updated = db.updateSeminar(req.params.id, req.body);
      if (!updated) {
        res.status(404).json({ success: false, error: 'Seminar not found' });
        return;
      }
      res.json({ success: true, data: updated });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/seminars/:id/cancel', (req: Request, res: Response) => {
    try {
      const { reason } = req.body;
      const result = db.cancelSeminar(req.params.id, reason);
      if (!result) {
        res.status(404).json({ success: false, error: 'Seminar not found' });
        return;
      }
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // 2. Registrations API
  app.get('/api/registrations', (req: Request, res: Response) => {
    try {
      const { userEmail, seminarId, status } = req.query;
      const list = db.getRegistrations({
        userEmail: userEmail as string,
        seminarId: seminarId as string,
        status: status as string,
      });
      res.json({ success: true, data: list });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/registrations', (req: Request, res: Response) => {
    try {
      const { seminarId, participantName, participantEmail, institution, department, yearOfStudy, phone } = req.body;
      if (!seminarId || !participantName || !participantEmail || !institution || !department || !yearOfStudy) {
        res.status(400).json({ success: false, message: 'All required registration fields must be provided.' });
        return;
      }

      const result = db.registerForSeminar({
        seminarId,
        participantName,
        participantEmail,
        institution,
        department,
        yearOfStudy,
        phone,
      });

      if (!result.success) {
        res.status(400).json(result);
        return;
      }

      res.status(201).json(result);
    } catch (err: any) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  app.post('/api/registrations/:id/cancel', (req: Request, res: Response) => {
    try {
      const { userEmail } = req.body;
      const result = db.cancelRegistration(req.params.id, userEmail);
      if (!result.success) {
        res.status(400).json(result);
        return;
      }
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // Calendar .ics download
  app.get('/api/registrations/:id/ics', (req: Request, res: Response) => {
    try {
      const registrations = db.getRegistrations();
      const reg = registrations.find(r => r.id === req.params.id);
      if (!reg) {
        res.status(404).send('Registration not found');
        return;
      }

      const seminar = db.getSeminarById(reg.seminarId);
      const cleanDate = reg.seminarDate.replace(/-/g, '');
      const icsData = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//Seminar Information Bot//College Portal//EN',
        'CALSCALE:GREGORIAN',
        'METHOD:PUBLISH',
        'BEGIN:VEVENT',
        `UID:${reg.ticketCode}@seminarbot.college.edu`,
        `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, '').split('.')[0]}Z`,
        `DTSTART:${cleanDate}T043000Z`,
        `DTEND:${cleanDate}T073000Z`,
        `SUMMARY:${reg.seminarTitle}`,
        `DESCRIPTION:Confirmed Registration (Ticket: ${reg.ticketCode}). ${seminar?.shortDescription || ''}`,
        `LOCATION:${reg.seminarVenue}`,
        'STATUS:CONFIRMED',
        'END:VEVENT',
        'END:VCALENDAR',
      ].join('\r\n');

      res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="seminar-${reg.ticketCode}.ics"`);
      res.send(icsData);
    } catch (err: any) {
      res.status(500).send(err.message);
    }
  });

  // CSV Export for Organizers
  app.get('/api/organizer/attendees/:seminarId/export', (req: Request, res: Response) => {
    try {
      const seminar = db.getSeminarById(req.params.seminarId);
      if (!seminar) {
        res.status(404).send('Seminar not found');
        return;
      }
      const attendees = db.getRegistrations({ seminarId: seminar.id });

      const header = ['Ticket Code', 'Participant Name', 'Email', 'Institution', 'Department', 'Year of Study', 'Phone', 'Registration Date', 'Status'];
      const rows = attendees.map(a => [
        `"${a.ticketCode}"`,
        `"${a.participantName}"`,
        `"${a.participantEmail}"`,
        `"${a.institution}"`,
        `"${a.department}"`,
        `"${a.yearOfStudy}"`,
        `"${a.phone || ''}"`,
        `"${a.registeredAt}"`,
        `"${a.status}"`,
      ]);

      const csvContent = [header.join(','), ...rows.map(r => r.join(','))].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${seminar.slug}-attendees.csv"`);
      res.send(csvContent);
    } catch (err: any) {
      res.status(500).send(err.message);
    }
  });

  // 3. Announcements API
  app.get('/api/announcements', (_req: Request, res: Response) => {
    try {
      const list = db.getAnnouncements();
      res.json({ success: true, data: list });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/announcements', (req: Request, res: Response) => {
    try {
      const { title, content, priority, author, department } = req.body;
      if (!title || !content) {
        res.status(400).json({ success: false, error: 'Title and content are required' });
        return;
      }
      const created = db.createAnnouncement({
        title,
        content,
        priority: priority || 'normal',
        author: author || 'College Administration',
        department: department || 'Academic Affairs',
        pinned: req.body.pinned || false,
      });
      res.status(201).json({ success: true, data: created });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // 4. Notifications API
  app.get('/api/notifications', (req: Request, res: Response) => {
    try {
      const { userEmail } = req.query;
      const list = db.getNotifications(userEmail as string);
      res.json({ success: true, data: list });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.patch('/api/notifications/:id/read', (req: Request, res: Response) => {
    try {
      const success = db.markNotificationRead(req.params.id);
      res.json({ success });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/notifications/mark-all-read', (req: Request, res: Response) => {
    try {
      const { userEmail } = req.body;
      db.markAllNotificationsRead(userEmail);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // 5. Dashboard Stats API
  app.get('/api/stats', (req: Request, res: Response) => {
    try {
      const { userEmail } = req.query;
      const stats = db.getStats(userEmail as string);
      res.json({ success: true, data: stats });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // 6. AI Seminar Assistant API (Server-Side Gemini Integration)
  app.post('/api/chat', async (req: Request, res: Response) => {
    try {
      const { message, conversationHistory, language } = req.body;
      if (!message || typeof message !== 'string') {
        res.status(400).json({ success: false, error: 'A valid message string is required.' });
        return;
      }

      const botResponse = await askSeminarBot({
        message,
        conversationHistory: Array.isArray(conversationHistory) ? conversationHistory : [],
        language: language || 'en',
      });

      res.json({ success: true, data: botResponse });
    } catch (err: any) {
      console.error('Chat endpoint error:', err);
      res.status(500).json({ success: false, error: err.message || 'Error processing AI chat' });
    }
  });

  // 7. Vite middleware or static serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Seminar Information Bot server is listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
