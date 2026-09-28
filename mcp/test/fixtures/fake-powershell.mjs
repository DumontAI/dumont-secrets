#!/usr/bin/env node
// Fake powershell for the tests (see fake-credtool.mjs).
import { powershell } from './fake-credtool.mjs';

await powershell(process.argv.slice(2));
