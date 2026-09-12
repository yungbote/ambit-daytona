/*
 * Copyright 2026 Ambit Platforms
 * SPDX-License-Identifier: AGPL-3.0
 */

import { MigrationInterface, QueryRunner } from 'typeorm'

export class Migration1789257600000 implements MigrationInterface {
  name = 'Migration1789257600000'

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "runner"
      ADD "schedulingFenceOwner" character varying(128),
      ADD "schedulingFenceToken" uuid`)
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "runner"
      DROP COLUMN "schedulingFenceToken",
      DROP COLUMN "schedulingFenceOwner"`)
  }
}
