-- STREAMING_CHUNK: ตั้งค่าโครงสร้างตารางพื้นฐาน
-- 1. สร้างตารางและฟังก์ชันพื้นฐาน
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);

CREATE TABLE students (
    id VARCHAR(5) PRIMARY KEY, -- รหัส 5 หลัก
    title VARCHAR(20),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    section VARCHAR(10),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT,
    CONSTRAINT chk_student_id CHECK (id ~ '^[0-9]{5}$')
);

CREATE TABLE attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(4) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind)
);

CREATE TABLE progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    done BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, unit)
);

CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- STREAMING_CHUNK: สร้างฟังก์ชันจัดการสิทธิ์และการสมัครสมาชิก
-- 2. Security Definer Function สำหรับตรวจสอบความเป็นครู
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
$$;

-- 3. Trigger สำหรับผูกบัญชี auth.users กับนักเรียน (ป้องกันการสมัครมั่ว)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    extracted_id VARCHAR(5);
BEGIN
    -- กรณีเป็นครู (อีเมลไม่ขึ้นด้วยตัวเลข 5 หลัก)
    IF NEW.email !~ '^[0-9]{5}@banmaed\.ac\.th$' THEN
        RETURN NEW;
    END IF;

    -- กรณีนักเรียน
    extracted_id := SUBSTRING(NEW.email FROM '^([0-9]{5})@');
    
    -- ตรวจสอบว่ามีรหัสในฐานข้อมูลและยังไม่ถูกใช้
    IF EXISTS (SELECT 1 FROM students WHERE id = extracted_id AND user_id IS NULL) THEN
        UPDATE students SET user_id = NEW.id WHERE id = extracted_id;
        RETURN NEW;
    ELSE
        RAISE EXCEPTION 'รหัสนักเรียนไม่ถูกต้อง หรือถูกใช้งานไปแล้ว';
    END IF;
END;
$$;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- STREAMING_CHUNK: ตั้งค่า Row Level Security (RLS)
-- 4. เปิด RLS ทุกตาราง
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- ยกเลิกสิทธิ์ anon เพื่อความปลอดภัย
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

-- นโยบายตาราง teachers
CREATE POLICY "ครูเห็นข้อมูลตัวเอง" ON teachers FOR SELECT TO authenticated USING (user_id = auth.uid());

-- นโยบายตาราง students
CREATE POLICY "นักเรียนเห็นข้อมูลตัวเองหรือครูเห็นทั้งหมด" ON students FOR SELECT TO authenticated 
USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "นักเรียนแก้ไขรูปตัวเองได้" ON students FOR UPDATE TO authenticated 
USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- นโยบายตาราง attempts
CREATE POLICY "นักเรียนเพิ่มข้อมูลสอบตัวเอง" ON attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "นักเรียนดูของตัวเองหรือครูดูทั้งหมด" ON attempts FOR SELECT TO authenticated 
USING (user_id = auth.uid() OR is_teacher());

-- นโยบายตาราง progress
CREATE POLICY "จัดการความก้าวหน้าตนเอง" ON progress FOR ALL TO authenticated 
USING (user_id = auth.uid() OR is_teacher()) WITH CHECK (user_id = auth.uid() OR is_teacher());

-- นโยบายตาราง submissions (นักเรียนห้ามแก้ score/comment)
CREATE POLICY "นักเรียนส่งงาน" ON submissions FOR INSERT TO authenticated 
WITH CHECK (user_id = auth.uid() AND score IS NULL AND teacher_comment IS NULL);
CREATE POLICY "นักเรียนดูงานตัวเองและครูดูทั้งหมด" ON submissions FOR SELECT TO authenticated 
USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "ครูตรวจงานและให้คะแนน" ON submissions FOR UPDATE TO authenticated 
USING (is_teacher()) WITH CHECK (is_teacher());

-- นโยบายตาราง materials
CREATE POLICY "ทุกคนดูสื่อได้" ON materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "ครูจัดการสื่อได้" ON materials FOR ALL TO authenticated 
USING (is_teacher()) WITH CHECK (is_teacher());

-- STREAMING_CHUNK: สร้าง View และตั้งค่า Storage
-- 5. View สำหรับครู (Security Invoker)
CREATE OR REPLACE VIEW teacher_results_view WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id, s.title, s.first_name, s.last_name, s.section,
    pre.score AS pre_score, post.score AS post_score,
    (SELECT COUNT(*) FROM progress WHERE user_id = s.user_id AND done = true) AS modules_done
FROM students s
LEFT JOIN attempts pre ON s.user_id = pre.user_id AND pre.kind = 'pre'
LEFT JOIN attempts post ON s.user_id = post.user_id AND post.kind = 'post'
WHERE s.user_id IS NOT NULL;

-- 6. Storage Setup
INSERT INTO storage.buckets (id, name, public) VALUES 
('photos', 'photos', false),
('submissions', 'submissions', false),
('materials', 'materials', false);

-- Storage RLS (photos)
CREATE POLICY "ดูรูปตัวเองหรือครูดู" ON storage.objects FOR SELECT TO authenticated 
USING (bucket_id = 'photos' AND ((auth.uid()::text = (string_to_array(name, '/'))[1]) OR is_teacher()));
CREATE POLICY "นักเรียนอัปโหลดรูปโฟลเดอร์ตัวเอง" ON storage.objects FOR INSERT TO authenticated 
WITH CHECK (bucket_id = 'photos' AND auth.uid()::text = (string_to_array(name, '/'))[1]);

-- Storage RLS (submissions)
CREATE POLICY "ดูงานตัวเองหรือครูดู" ON storage.objects FOR SELECT TO authenticated 
USING (bucket_id = 'submissions' AND ((auth.uid()::text = (string_to_array(name, '/'))[1]) OR is_teacher()));
CREATE POLICY "นักเรียนอัปโหลดงานตัวเอง" ON storage.objects FOR INSERT TO authenticated 
WITH CHECK (bucket_id = 'submissions' AND auth.uid()::text = (string_to_array(name, '/'))[1]);

-- Storage RLS (materials)
CREATE POLICY "ทุกคนดูสื่อ" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "ครูจัดการสื่อ" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND is_teacher());

-- STREAMING_CHUNK: ข้อมูลจำลอง
-- 7. Insert ข้อมูลจำลองนักเรียน 6 แถว (วิธีนำเข้าจริงให้ใช้ CSV ผ่าน Supabase Table Editor โดยตั้งคอลัมน์ให้ตรงกัน)
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('10001', 'ด.ช.', 'สมชาย', 'ใจดี', 'ม.1/1'),
('10002', 'ด.ญ.', 'สมหญิง', 'รักเรียน', 'ม.1/1'),
('10003', 'ด.ช.', 'มานะ', 'อดทน', 'ม.1/1'),
('10004', 'ด.ญ.', 'ปิติ', 'ยินดี', 'ม.1/2'),
('10005', 'ด.ช.', 'ชูใจ', 'เก่งกล้า', 'ม.1/2'),
('10006', 'ด.ญ.', 'วีระ', 'หาญกล้า', 'ม.1/2');

-- 8. ตั้งค่าบัญชีครู (ให้ผู้สอนเปลี่ยน UUID ตรงนี้หลังจากที่สมัครสมาชิกด้วยอีเมลครูแล้วนำมายัดใส่)
-- INSERT INTO teachers (user_id) VALUES ('ใส่-UUID-ของบัญชีครู-ที่นี่');