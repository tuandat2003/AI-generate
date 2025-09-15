// File: server.js

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';

// --- KHỞI TẠO ---
const supabase = createClient(process.env.VITE_SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const app = express();
app.use(cors({ origin: 'http://localhost:5173' }));
app.use(express.json({ limit: '10mb' }));

// --- ACTIVITY TABLE SETUP ---
// Note: The activities table needs to be created manually in Supabase
// Run the SQL script in create_activity_table.sql in your Supabase SQL editor
// The table will be created with proper schema, indexes, and RLS policies

// Cấu hình Multer để lưu file tạm thời trong bộ nhớ
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Password validation function
const validatePassword = (password) => {
    const minLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return {
        isValid: minLength && hasUppercase && hasSpecialChar,
        errors: {
            minLength: !minLength ? 'Mật khẩu phải có ít nhất 8 ký tự' : null,
            hasUppercase: !hasUppercase ? 'Mật khẩu phải có ít nhất 1 chữ cái viết hoa' : null,
            hasSpecialChar: !hasSpecialChar ? 'Mật khẩu phải có ít nhất 1 ký tự đặc biệt (!@#$%^&*)' : null
        }
    };
};

// --- API XÁC THỰC (AUTH) ---

// API Đăng Ký
app.post('/api/auth/register', async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!email || !password || !fullName) {
        return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ họ tên, email và mật khẩu.' });
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
        const errorMessages = Object.values(passwordValidation.errors).filter(Boolean);
        return res.status(400).json({ 
            error: 'Mật khẩu không đáp ứng yêu cầu bảo mật',
            details: errorMessages
        });
    }

    try {
        const { data: existingUser } = await supabase.from('users').select('id').eq('email', email).single();
        if (existingUser) {
            return res.status(400).json({ error: 'Email đã tồn tại trong hệ thống.' });
        }

        const hashedPassword = await bcrypt.hash(password, 12); // Tăng từ 10 lên 12 rounds

        const { data: newUser, error } = await supabase
            .from('users')
            .insert({ full_name: fullName, email, hashed_password: hashedPassword })
            .select('id, email, full_name')
            .single();

        if (error) throw error;
        
        res.status(201).json({ 
            message: 'Tài khoản đã được tạo thành công!', 
            user: newUser 
        });
    } catch (err) {
        console.error('[/api/auth/register] Error:', err);
        res.status(500).json({ error: 'Lỗi hệ thống trong quá trình đăng ký.' });
    }
});

// API Đăng Nhập
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
        if (error || !user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.hashed_password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        
        res.json({ token, user: { id: user.id, fullName: user.full_name, email: user.email, avatarUrl: user.avatar_url } });
    } catch (err) {
        console.error('[/api/auth/login] Error:', err);
        res.status(500).json({ error: 'Server error during login.' });
    }
});


// --- MIDDLEWARE BẢO VỆ "NGƯỜI GÁC CỔNG" ---
const protect = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Not authenticated, no token provided.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Gắn thông tin người dùng (userId, email) vào request
        next(); // Cho phép đi tiếp
    } catch (err) {
        res.status(401).json({ error: 'Not authenticated, token is invalid.' });
    }
};

// Thêm vào server.js

// Middleware kiểm tra admin
const adminProtect = (req, res, next) => {
    console.log('=== 🔐 ADMIN MIDDLEWARE CHECK ===');
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ No admin auth header');
        return res.status(401).json({ error: 'Not authenticated, no token provided.' });
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('✅ Token decoded, checking admin status:', {
            userId: decoded.userId,
            email: decoded.email,
            role: decoded.role
        });
        
        // Kiểm tra role admin (có thể là email hoặc role field)
        if (decoded.email !== 'admin@dreamina.com' && decoded.role !== 'admin') {
            console.log('❌ User is not admin');
            return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        console.log('❌ Admin JWT verify error:', err.message);
        res.status(401).json({ error: 'Invalid admin token.' });
    }
};

// API lấy danh sách tất cả người dùng (chỉ admin)
app.get('/api/admin/users', adminProtect, async (req, res) => {
    console.log('=== 👥 GET ALL USERS ADMIN API ===');
    const { page = 1, limit = 10, search = '' } = req.query;
    const offset = (page - 1) * limit;
    
    try {
        let query = supabase
            .from('users')
            .select(`
                id, 
                full_name, 
                email, 
                bio, 
                avatar_url, 
                created_at, 
                updated_at
            `)
            .order('created_at', { ascending: false });
            
        // Tìm kiếm nếu có
        if (search) {
            query = query.or(`full_name.ilike.%${search}%,email.ilike.%${search}%`);
        }
        
        // Phân trang
        query = query.range(offset, offset + parseInt(limit) - 1);
        
        const { data: users, error, count } = await query;
        
        if (error) throw error;
        
        // Đếm tổng số user
        const { count: totalUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });
        
        console.log(`✅ Retrieved ${users.length} users`);
        
        res.json({
            success: true,
            users: users || [],
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(totalUsers / limit),
                totalUsers: totalUsers,
                limit: parseInt(limit)
            }
        });
        
    } catch (error) {
        console.error('❌ Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users', details: error.message });
    }
});

// API lấy thống kê tổng quan (chỉ admin)
app.get('/api/admin/stats', adminProtect, async (req, res) => {
    console.log('=== 📊 GET ADMIN STATS API ===');
    
    try {
        // Thống kê người dùng
        const { count: totalUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });
            
        // Thống kê ảnh được tạo
        const { count: totalImages } = await supabase
            .from('images')
            .select('*', { count: 'exact', head: true });
            
        // Người dùng mới trong 30 ngày qua
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const { count: newUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .gte('created_at', thirtyDaysAgo.toISOString());
            
        // Ảnh được tạo trong 30 ngày qua
        const { count: recentImages } = await supabase
            .from('images')
            .select('*', { count: 'exact', head: true })
            .gte('created_at', thirtyDaysAgo.toISOString());
        
        console.log('✅ Stats retrieved successfully');
        
        res.json({
            success: true,
            stats: {
                totalUsers: totalUsers || 0,
                totalImages: totalImages || 0,
                newUsers: newUsers || 0,
                recentImages: recentImages || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Get stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
    }
});

// API lấy chi tiết user và ảnh của user (chỉ admin)
app.get('/api/admin/users/:userId', adminProtect, async (req, res) => {
    console.log('=== 👤 GET USER DETAILS ADMIN API ===');
    const { userId } = req.params;
    
    try {
        // Lấy thông tin user
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();
            
        if (userError) throw userError;
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        // Lấy ảnh của user
        const { data: images, error: imagesError } = await supabase
            .from('images')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false });
            
        if (imagesError) throw imagesError;
        
        console.log(`✅ Retrieved user ${userId} with ${images?.length || 0} images`);
        
        res.json({
            success: true,
            user: {
                ...user,
                hashed_password: undefined // Không trả về password
            },
            images: images || []
        });
        
    } catch (error) {
        console.error('❌ Get user details error:', error);
        res.status(500).json({ error: 'Failed to fetch user details', details: error.message });
    }
});

// API xóa user (chỉ admin)
app.delete('/api/admin/users/:userId', adminProtect, async (req, res) => {
    console.log('=== 🗑️ DELETE USER ADMIN API ===');
    const { userId } = req.params;
    
    try {
        // Xóa tất cả ảnh của user trước
        const { data: userImages, error: getImagesError } = await supabase
            .from('images')
            .select('file_path')
            .eq('user_id', userId);
            
        if (!getImagesError && userImages?.length > 0) {
            // Xóa files khỏi storage
            const filePaths = userImages.map(img => img.file_path);
            await supabase.storage.from('images').remove(filePaths);
            
            // Xóa records khỏi database
            await supabase.from('images').delete().eq('user_id', userId);
        }
        
        // Xóa user
        const { error: deleteUserError } = await supabase
            .from('users')
            .delete()
            .eq('id', userId);
            
        if (deleteUserError) throw deleteUserError;
        
        console.log(`✅ User ${userId} deleted successfully`);
        
        res.json({
            success: true,
            message: 'User and all associated data deleted successfully'
        });
        
    } catch (error) {
        console.error('❌ Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user', details: error.message });
    }
});


// --- HÀM GHI LOG HOẠT ĐỘNG ---
const logActivity = async (userId, action, imageId = null, additionalData = {}) => {
    try {
        const { error } = await supabase
            .from('activities')
            .insert({
                user_id: userId,
                action: action,
                image_id: imageId,
                timestamp: new Date().toISOString(),
                additional_data: additionalData
            });
        
        if (error) {
            console.error('❌ Error logging activity:', error);
            if (error.code === 'PGRST116' || error.message.includes('relation "activities" does not exist')) {
                console.error('❌ Activities table does not exist. Please run the SQL script in create_activity_table.sql');
            }
        } else {
            console.log(`✅ Activity logged: ${action} for user ${userId}`);
        }
    } catch (err) {
        console.error('❌ Error in logActivity function:', err);
        if (err.message && err.message.includes('activities')) {
            console.error('❌ Activities table may not exist. Please check your database setup.');
        }
    }
};

// --- CÁC API CẦN BẢO VỆ ---
// Tất cả các API dưới đây sẽ yêu cầu có "vé thông hành" hợp lệ.
// Chúng ta chỉ cần thêm `protect` vào giữa đường dẫn và hàm xử lý.

app.post('/api/generate-image', protect, async (req, res) => {
    console.log('=== 🎨 GENERATE IMAGE ENDPOINT HIT ===');
    const userId = req.user.userId;
    const { prompt } = req.body;
    
    console.log('Request details:', {
        userId,
        prompt: prompt?.substring(0, 100) + '...',
        bodyKeys: Object.keys(req.body),
        headers: {
            'content-type': req.headers['content-type'],
            'authorization': req.headers.authorization?.substring(0, 30) + '...'
        }
    });

    if (!prompt) {
        console.log('❌ No prompt provided');
        return res.status(400).json({ error: 'Prompt is required' });
    }

    try {
        console.log(`[Generate Image] User ${userId} generating with prompt: "${prompt}"`);
        
        // Gọi đến Colab API
        const COLAB_API_URL = process.env.VITE_AI_GENERATOR_API_URL || 'https://e9ddc7ce508d.ngrok-free.app';
        
        const response = await fetch(`${COLAB_API_URL}/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'ngrok-skip-browser-warning': 'true' // Bỏ qua warning của ngrok
            },
            body: JSON.stringify({ prompt })
        });

        if (!response.ok) {
            throw new Error(`Colab API error: ${response.status}`);
        }

        // Lấy ảnh từ Colab dưới dạng blob
        const imageBlob = await response.blob();
        const imageBuffer = Buffer.from(await imageBlob.arrayBuffer());

        // Tạo tên file unique
        const fileName = `${userId}_${Date.now()}_generated.png`;
        const filePath = `generated/${fileName}`;

        // Upload ảnh lên Supabase Storage
        const { error: uploadError } = await supabase.storage
            .from('images') // Đảm bảo bucket 'images' đã tồn tại
            .upload(filePath, imageBuffer, {
                contentType: 'image/png',
                upsert: false
            });

        if (uploadError) {
            console.error('Supabase upload error:', uploadError);
            throw uploadError;
        }

        // Lấy public URL
        const { data: publicUrlData } = supabase.storage
            .from('images')
            .getPublicUrl(filePath);

        const imageUrl = publicUrlData.publicUrl;

        // Lưu thông tin vào database
        const { data: imageRecord, error: dbError } = await supabase
            .from('images')
            .insert({
                user_id: userId,
                prompt: prompt,
                image_url: imageUrl,
                file_path: filePath
            })
            .select()
            .single();

        if (dbError) {
            console.error('Database save error:', dbError);
            throw dbError;
        }

        console.log(`[Generate Image] Success for user ${userId}: ${imageUrl}`);
        
        // Ghi log hoạt động generate
        await logActivity(userId, 'generate', imageRecord.id, { prompt: prompt.substring(0, 100) });
        
        res.json({
            success: true,
            imageUrl: imageUrl,
            imageId: imageRecord.id,
            message: 'Image generated successfully'
        });

    } catch (error) {
        console.error('[Generate Image] Error:', error);
        res.status(500).json({
            error: 'Failed to generate image',
            details: error.message
        });
    }
});

app.get('/api/my-creations', protect, async (req, res) => {
    const userId = req.user.userId;
    try {
        const { data, error } = await supabase.from('images').select('*').eq('user_id', userId).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch creations.' });
    }
});

// API xóa hình ảnh
app.delete('/api/images/:imageId', protect, async (req, res) => {
    console.log('=== 🗑️ DELETE IMAGE API HIT ===');
    const userId = req.user.userId;
    const { imageId } = req.params;
    
    console.log('Delete request details:', {
        userId,
        imageId,
        headers: {
            'authorization': req.headers.authorization?.substring(0, 30) + '...'
        }
    });
    
    try {
        // Kiểm tra xem hình ảnh có thuộc về user này không
        const { data: image, error: fetchError } = await supabase
            .from('images')
            .select('*')
            .eq('id', imageId)
            .eq('user_id', userId)
            .single();
            
        console.log('Image fetch result:', { image, fetchError });
            
        if (fetchError) {
            console.error('Fetch error:', fetchError);
            throw fetchError;
        }
        
        if (!image) {
            console.log('Image not found or not owned by user');
            return res.status(404).json({ 
                success: false,
                error: 'Hình ảnh không tồn tại hoặc không thuộc về bạn.' 
            });
        }

        // Xóa file khỏi storage
        if (image.file_path) {
            console.log('Deleting from storage:', image.file_path);
            const { error: storageError } = await supabase.storage
                .from('images')
                .remove([image.file_path]);
                
            if (storageError) {
                console.error('Storage delete error:', storageError);
                // Tiếp tục xóa record khỏi database dù có lỗi storage
            } else {
                console.log('Storage deletion successful');
            }
        }

        // Xóa record khỏi database
        console.log('Deleting from database...');
        const { error: deleteError } = await supabase
            .from('images')
            .delete()
            .eq('id', imageId)
            .eq('user_id', userId);
            
        if (deleteError) {
            console.error('Database delete error:', deleteError);
            throw deleteError;
        }

        console.log(`✅ [Delete Image] User ${userId} deleted image ${imageId} successfully`);
        
        // Ghi log hoạt động delete
        await logActivity(userId, 'delete', imageId, { imageUrl: image.image_url });
        
        res.json({ 
            success: true, 
            message: 'Hình ảnh đã được xóa thành công!' 
        });

    } catch (err) {
        console.error('❌ [/api/images/:imageId DELETE] Error:', err);
        res.status(500).json({ 
            success: false,
            error: 'Lỗi hệ thống trong quá trình xóa hình ảnh.',
            details: err.message 
        });
    }
});

app.get('/api/profile', protect, async (req, res) => {
    const userId = req.user.userId;
    try {
        const { data, error } = await supabase.from('users').select('id, full_name, email, bio, avatar_url, created_at').eq('id', userId).single();
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch profile.' });
    }
});

app.patch(
    '/api/profile', 
    protect, 
    upload.single('avatar'), // Middleware của Multer để xử lý 1 file tên là 'avatar'
    async (req, res) => {
        const userId = req.user.userId;
        const { name, bio } = req.body;
        let avatarUrl = null;

        try {
            // BƯỚC 1: Xử lý file avatar nếu có
            if (req.file) {
                console.log(`[Server] Received avatar for user ${userId}`);
                const file = req.file;
                const filePath = `${userId}/${Date.now()}_${file.originalname}`;

                const { error: uploadError } = await supabase.storage
                    .from('avatars') // Upload vào bucket 'avatars'
                    .upload(filePath, file.buffer, { contentType: file.mimetype });

                if (uploadError) throw uploadError;

                const { data: publicUrlData } = supabase.storage.from('avatars').getPublicUrl(filePath);
                avatarUrl = publicUrlData.publicUrl;
                console.log(`[Server] New avatar URL: ${avatarUrl}`);
            }

            // BƯỚC 2: Cập nhật database
            const updateData = {
                full_name: name,
                bio: bio,
                updated_at: new Date(),
            };

            // Chỉ thêm avatar_url vào object nếu có avatar mới
            if (avatarUrl) {
                updateData.avatar_url = avatarUrl;
            }

            const { data, error } = await supabase
                .from('users')
                .update(updateData)
                .eq('id', userId)
                .select()
                .single();
            
            if (error) throw error;
            
            res.json({ success: true, profile: data });
        } catch (err) {
            console.error('[/api/profile PATCH] Error:', err);
            res.status(500).json({ error: 'Failed to update profile', details: err.message });
        }
    }
);

// API đổi mật khẩu
app.patch('/api/change-password', protect, async (req, res) => {
    const userId = req.user.userId;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ 
            error: 'Vui lòng cung cấp mật khẩu hiện tại và mật khẩu mới.' 
        });
    }

    // Validate password strength
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
        const errorMessages = Object.values(passwordValidation.errors).filter(Boolean);
        return res.status(400).json({ 
            error: 'Mật khẩu mới không đáp ứng yêu cầu bảo mật',
            details: errorMessages
        });
    }

    try {
        // Lấy thông tin user hiện tại
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('hashed_password')
            .eq('id', userId)
            .single();

        if (userError) throw userError;
        if (!user) {
            return res.status(404).json({ error: 'Không tìm thấy người dùng.' });
        }

        // Kiểm tra mật khẩu hiện tại
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.hashed_password);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({ error: 'Mật khẩu hiện tại không đúng.' });
        }

        // Hash mật khẩu mới
        const hashedNewPassword = await bcrypt.hash(newPassword, 12);

        // Cập nhật mật khẩu mới
        const { error: updateError } = await supabase
            .from('users')
            .update({ 
                hashed_password: hashedNewPassword,
                updated_at: new Date()
            })
            .eq('id', userId);

        if (updateError) throw updateError;

        console.log(`[Change Password] User ${userId} changed password successfully`);
        
        res.json({ 
            success: true, 
            message: 'Mật khẩu đã được thay đổi thành công!' 
        });

    } catch (err) {
        console.error('[/api/change-password] Error:', err);
        res.status(500).json({ 
            error: 'Lỗi hệ thống trong quá trình đổi mật khẩu.',
            details: err.message 
        });
    }
});

// --- API LỊCH SỬ HOẠT ĐỘNG ---

// Test endpoint to check if activities table exists
app.get('/api/test-activities', protect, async (req, res) => {
    console.log('=== 🧪 TEST ACTIVITIES TABLE ===');
    try {
        const { data, error } = await supabase
            .from('activities')
            .select('id')
            .limit(1);
            
        if (error) {
            console.error('❌ Activities table test failed:', error);
            return res.status(500).json({
                success: false,
                error: 'Activities table not found',
                details: error.message,
                suggestion: 'Please run the SQL script in create_activity_table.sql in your Supabase SQL Editor'
            });
        }
        
        console.log('✅ Activities table exists and is accessible');
        res.json({
            success: true,
            message: 'Activities table is ready',
            tableExists: true
        });
        
    } catch (err) {
        console.error('❌ Test activities error:', err);
        res.status(500).json({
            success: false,
            error: 'Database connection issue',
            details: err.message
        });
    }
});

// API lấy lịch sử hoạt động của user
app.get('/api/activities', protect, async (req, res) => {
    console.log('=== 📋 GET USER ACTIVITIES API ===');
    const userId = req.user.userId;
    const { page = 1, limit = 20, action = '' } = req.query;
    const offset = (page - 1) * limit;
    
    try {
        // First check if activities table exists by trying a simple query
        const { data: testData, error: testError } = await supabase
            .from('activities')
            .select('id')
            .limit(1);
            
        if (testError) {
            console.error('❌ Activities table does not exist or has issues:', testError);
            return res.status(500).json({ 
                error: 'Activities table not found', 
                details: 'Please create the activities table first by running the SQL script in create_activity_table.sql',
                suggestion: 'Go to Supabase SQL Editor and run the create_activity_table.sql script'
            });
        }
        
        let query = supabase
            .from('activities')
            .select(`
                id,
                action,
                image_id,
                timestamp,
                additional_data,
                images (
                    id,
                    prompt,
                    image_url
                )
            `)
            .eq('user_id', userId)
            .order('timestamp', { ascending: false });
            
        // Lọc theo action nếu có
        if (action) {
            query = query.eq('action', action);
        }
        
        // Phân trang
        query = query.range(offset, offset + parseInt(limit) - 1);
        
        const { data: activities, error, count } = await query;
        
        if (error) {
            console.error('❌ Query activities error:', error);
            throw error;
        }
        
        // Đếm tổng số activities
        let countQuery = supabase
            .from('activities')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId);
            
        if (action) {
            countQuery = countQuery.eq('action', action);
        }
        
        const { count: totalActivities } = await countQuery;
        
        console.log(`✅ Retrieved ${activities?.length || 0} activities for user ${userId}`);
        
        res.json({
            success: true,
            activities: activities || [],
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil((totalActivities || 0) / limit),
                totalActivities: totalActivities || 0,
                limit: parseInt(limit)
            }
        });
        
    } catch (error) {
        console.error('❌ Get activities error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch activities', 
            details: error.message,
            suggestion: 'Make sure the activities table exists in your Supabase database'
        });
    }
});

// API ghi log hoạt động download (được gọi từ frontend)
app.post('/api/activities/log', protect, async (req, res) => {
    console.log('=== 📝 LOG ACTIVITY API ===');
    const userId = req.user.userId;
    const { action, imageId, additionalData = {} } = req.body;
    
    if (!action) {
        return res.status(400).json({ error: 'Action is required' });
    }
    
    try {
        await logActivity(userId, action, imageId, additionalData);
        
        res.json({
            success: true,
            message: 'Activity logged successfully'
        });
        
    } catch (error) {
        console.error('❌ Log activity error:', error);
        res.status(500).json({ error: 'Failed to log activity', details: error.message });
    }
});


// --- KHỞI ĐỘNG SERVER ---
const PORT = process.env.PORT || 8787;
app.listen(PORT, () => {
  console.log(`✅ Server is running on http://localhost:${PORT}`);
});