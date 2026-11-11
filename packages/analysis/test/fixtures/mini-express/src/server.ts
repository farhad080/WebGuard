import express from 'express';
import { usersRouter } from './routes/users.js';

const app = express();
app.use(express.json());
app.use('/users', usersRouter);

app.listen(Number(process.env.PORT ?? 3000));

// TODO SECURITY: add rate limiting to /users before launch
