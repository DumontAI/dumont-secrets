#!/usr/bin/env node
// Fake security for the tests (see fake-credtool.mjs).
import { security } from './fake-credtool.mjs';

await security(process.argv.slice(2));
