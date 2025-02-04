import express from 'express';
import nodemailer from 'nodemailer';
import bodyParser from 'body-parser';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import path from 'path';
import { WebSocketServer } from 'ws';
import textToSpeech from '@google-cloud/text-to-speech';
import fs from 'fs';
import { fileURLToPath } from 'url';
import util from 'util';
import multer from 'multer';
import cloudinary from 'cloudinary';
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
  textToSpeech,
  fs,
  fileURLToPath,
  util,
  multer,
  cloudinary,
  session,
  axios
};
