require("dotenv").config();
const pg = require("pg");
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

async function migrate() {
  try {
    // Check current columns
    const cols = await pool.query(
      "SELECT column_name, is_nullable FROM information_schema.columns WHERE table_name = 'User'"
    );
    console.log(
      "Current columns:",
      cols.rows.map((r) => r.column_name + "(" + r.is_nullable + ")")
    );

    // Make hashedPassword nullable
    await pool.query(
      'ALTER TABLE "User" ALTER COLUMN "hashedPassword" DROP NOT NULL'
    );
    console.log("✓ hashedPassword is now nullable");

    // Add image column if not exists
    const hasImage = cols.rows.find((r) => r.column_name === "image");
    if (!hasImage) {
      await pool.query('ALTER TABLE "User" ADD COLUMN "image" TEXT');
      console.log("✓ image column added");
    } else {
      console.log("✓ image column already exists");
    }

    // Verify
    const updated = await pool.query(
      "SELECT column_name, is_nullable, data_type FROM information_schema.columns WHERE table_name = 'User' ORDER BY ordinal_position"
    );
    console.log("\nUpdated schema:");
    updated.rows.forEach((r) =>
      console.log(`  ${r.column_name}: ${r.data_type} (nullable: ${r.is_nullable})`)
    );

    console.log("\n✓ Migration complete!");
  } catch (e) {
    console.error("Error:", e.message);
  } finally {
    pool.end();
  }
}

migrate();
