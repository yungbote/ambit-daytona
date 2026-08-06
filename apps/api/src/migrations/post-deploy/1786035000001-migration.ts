/*
 * Copyright 2026 Ambit Platforms
 * SPDX-License-Identifier: AGPL-3.0
 */

import { MigrationInterface, QueryRunner } from 'typeorm'

export class Migration1786035000001 implements MigrationInterface {
  name = 'Migration1786035000001'
  readonly transaction = false

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_sandbox_auto_destroy_at" ON "sandbox" ("autoDestroyAt") WHERE "autoDestroyAt" IS NOT NULL`,
    )
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX CONCURRENTLY IF EXISTS "idx_sandbox_auto_destroy_at"`)
  }
}
