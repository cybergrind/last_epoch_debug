#!/usr/bin/env python3
"""
Uses ydotool to press some keys.
There are skills, each skill has a cooldown, so we need to press after the cooldown is over.
Each skill has a time to live, when the time is over, we need to stop pressing loop.
Time to live is updated by calling http api.
"""

import argparse
import asyncio
import logging
import time
from subprocess import run

import uvicorn
from fastapi import FastAPI
from keycodes import KEYCODES


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('keypress_server')


SKILL_LOCK = asyncio.Lock()
app = FastAPI()


class Skill:
    def __init__(self, name: str, key: str, cooldown: float, ttl: float = 3):
        self.name = name
        self.key = key
        self.cooldown = cooldown
        self.default_ttl = ttl
        self.ttl = 0
        self.last_used = 0
        self.use_time = 0.01
        self.skill_loop_task = None

    def key_action(self, key, down=True):
        down = 1 if down else 0
        cmd = f'ydotool key {KEYCODES[key]}:{down}'
        run(cmd, shell=True)
        log.debug(f'{cmd=}')

    async def use(self):
        # Use the skill (press the key)
        log.info(f'Using skill {self.name} ({self.key})')
        self.last_used = time.time()
        async with SKILL_LOCK:
            self.key_action(self.key, down=True)
            await asyncio.sleep(self.use_time)
            self.key_action(self.key, down=False)

    async def skill_loop(self):
        # Sleep until the cooldown is over
        while True:
            t = time.time()
            if (self.last_used + self.cooldown) < t:
                await self.use()
            if self.ttl < t:
                break
            await asyncio.sleep(0.01)
        self.skill_loop_task = None

    async def activate(self):
        # Start the skill loop if not already running
        self.ttl = time.time() + self.default_ttl
        if self.skill_loop_task is None:
            self.skill_loop_task = asyncio.create_task(self.skill_loop())
            log.info(f'Started skill loop for {self.name}')
        else:
            t = time.time()
            next_call = self.last_used + self.cooldown
            log.info(f'Expect next call in: {next_call - t:.2f} seconds')


SKILLS = {
    'dive_bomb': Skill('dive_bomb', 'e', 0.5),
    'falcon_strikes': Skill('falcon_strikes', 'w', 7),
    'smoke_bomb': Skill('smoke_bomb', 'q', 1),
    'decoy': Skill('decoy', 't', 8.6),
    'heal': Skill('heal', 'r', 8),
}


@app.get('/skill/{skill_name}')
async def activate_skill(skill_name: str):
    """
    Activate a skill by its name.
    """
    log.info(f'Activating skill: {skill_name}')
    if skill_name == 'aerial assault':
        for skill in SKILLS.values():
            await skill.activate()
    return {'status': 'ok', 'skill': skill_name}


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    # parser.add_argument('-m', '--mode', default='auto', choices=['auto', 'manual'])
    # parser.add_argument('-l', '--ll', dest='ll', action='store_true', help='help')
    return parser.parse_args()


def main():
    # run server on port 8766
    log.info('Starting server...')
    uvicorn.run(app, host='0.0.0.0', port=8766)


if __name__ == '__main__':
    main()
