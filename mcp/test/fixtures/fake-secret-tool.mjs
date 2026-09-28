#!/usr/bin/env node
// Fake secret-tool for the tests (see fake-credtool.mjs).
import { secretTool } from './fake-credtool.mjs';

await secretTool(process.argv.slice(2));
