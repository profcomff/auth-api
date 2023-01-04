import logging

import uvicorn

from auth_backend.routes import app

if __name__ == '__main__':

    logging.basicConfig(
        filename=f'logger_{__name__}.log',
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    uvicorn.run(app)
