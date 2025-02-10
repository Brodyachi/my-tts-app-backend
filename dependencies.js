import express from 'express';
import nodemailer from 'nodemailer';
import bodyParser from 'body-parser';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import path from 'path';
import { WebSocketServer } from 'ws';
import fs from 'fs';
import { fileURLToPath } from 'url';
import util from 'util';
import multer from 'multer';
import session from 'express-session';
import axios from 'axios';

export {
  express,
  nodemailer,
  bodyParser,
  cors,
  bcrypt,
  pg,
  path,
  WebSocketServer,
  fs,
  fileURLToPath,
  util,
  multer,
  session,
  axios
};
