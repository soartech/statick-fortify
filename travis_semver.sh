#!/bin/bash
nvm install lts/*
npm install -D semantic-release @semantic-release/exec
npx semantic-release
