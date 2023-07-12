#!/bin/bash

alembic downgrade head-"$(alembic heads | wc -l | sed 's/ //g')"
alembic upgrade head