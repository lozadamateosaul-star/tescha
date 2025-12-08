import pool from './config/database.js';
import fs from 'fs';

async function ejecutarPruebas() {
    try {
        console.log('🧪 EJECUTANDO PRUEBAS EXHAUSTIVAS DE MÉTRICAS FINANCIERAS\n');

        // Leer el archivo SQL
        const sql = fs.readFileSync('./database/test_exhaustivo_metricas.sql', 'utf8');

        // Ejecutar el script
        const result = await pool.query(sql);

        console.log('✅ Script ejecutado correctamente\n');
        console.log('📊 RESULTADOS:\n');

        // Mostrar todos los resultados
        if (Array.isArray(result)) {
            result.forEach((res, index) => {
                if (res.rows && res.rows.length > 0) {
                    console.log(`\n--- Resultado ${index + 1} ---`);
                    console.table(res.rows);
                }
            });
        } else if (result.rows) {
            console.table(result.rows);
        }

        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

ejecutarPruebas();
