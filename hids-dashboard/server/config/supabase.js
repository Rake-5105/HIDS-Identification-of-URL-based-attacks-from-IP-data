const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;

let supabase = null;

const getSupabase = () => {
  if (!supabase && supabaseUrl && supabaseServiceKey &&
      !supabaseUrl.includes('your_supabase')) {
    supabase = createClient(supabaseUrl, supabaseServiceKey);
    console.log(`[${new Date().toISOString()}] Supabase connected: ${supabaseUrl}`);
  }
  return supabase;
};

module.exports = { getSupabase };
