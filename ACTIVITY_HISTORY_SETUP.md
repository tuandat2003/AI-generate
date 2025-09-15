# Activity History Feature Setup

## Overview
This feature implements user activity tracking as specified in US11, allowing users to view their activity history including image generation, editing, downloading, and deletion activities.

## Database Setup

### 1. Create the Activities Table
**IMPORTANT**: You need to manually create the activities table in Supabase. Follow these steps:

1. **Open Supabase Dashboard**:
   - Go to your Supabase project dashboard
   - Navigate to the "SQL Editor" tab

2. **Run the SQL Script**:
   - Copy the entire content from `create_activity_table.sql`
   - Paste it into the SQL editor
   - Click "Run" to execute the script

3. **What the script creates**:
   - `activities` table with proper schema
   - Indexes for performance optimization
   - Row Level Security (RLS) policies
   - Proper foreign key relationships

### 2. Verify Table Creation
After running the SQL script, verify the table was created by checking:
- Go to "Table Editor" in Supabase dashboard
- Look for the `activities` table
- Check that RLS is enabled (should show a shield icon)
- Verify the table has the correct columns: `id`, `user_id`, `action`, `image_id`, `timestamp`, `additional_data`, `created_at`

### 3. Test the Setup
Once the table is created, restart your server and test the activity logging:
1. Generate an image (should log "generate" activity)
2. Download an image (should log "download" activity)
3. Delete an image (should log "delete" activity)
4. View the activity history page to see logged activities

## Features Implemented

### Backend (server.js)
1. **Activity Logging Function**: `logActivity()` - logs user activities to database
2. **API Endpoints**:
   - `GET /api/activities` - Get user activity history with pagination and filtering
   - `POST /api/activities/log` - Log new activity (for frontend use)
3. **Automatic Logging**: Integrated into existing endpoints:
   - Image generation (`/api/generate-image`)
   - Image deletion (`/api/images/:imageId`)

### Frontend Components

#### ActivityHistory Component
- **Location**: `src/components/ActivityHistory.tsx`
- **Features**:
  - Display activity history with pagination
  - Filter by action type (generate, delete, download, view, edit)
  - Real-time activity display
  - Responsive design with mobile support
  - Activity details with image previews

#### Integration Points
1. **AIToolsPage**: Logs download activities
2. **UserProfilePage**: Logs view and download activities
3. **App.tsx**: Added navigation link to activity history

## Activity Types Tracked

1. **generate** - When user generates a new image
2. **delete** - When user deletes an image
3. **download** - When user downloads an image
4. **view** - When user views an image in their gallery
5. **edit** - When user edits an image (future feature)

## Database Schema

```sql
activities (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  action VARCHAR(50) NOT NULL,
  image_id UUID REFERENCES images(id),
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  additional_data JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
)
```

## Security Features

- **Row Level Security (RLS)**: Users can only see their own activities
- **Authentication Required**: All activity endpoints require valid JWT token
- **Data Validation**: Input validation on all activity logging endpoints

## Usage

### For Users
1. Navigate to "Lịch sử" (History) in the main navigation
2. View all activities with timestamps
3. Filter by action type using the filter buttons
4. Use pagination to browse through history

### For Developers
1. Use `logActivity(userId, action, imageId, additionalData)` to log activities
2. Call `/api/activities/log` endpoint for frontend logging
3. Use `/api/activities` endpoint to retrieve user activities

## Performance Considerations

- Indexes on `user_id`, `timestamp`, and `action` for fast queries
- Pagination to limit data transfer
- JSONB for flexible additional data storage
- Efficient queries with proper joins

## Future Enhancements

1. **Activity Analytics**: Charts and statistics
2. **Export Functionality**: Export activity history
3. **Real-time Updates**: WebSocket integration for live activity feed
4. **Activity Search**: Search through activity history
5. **Bulk Operations**: Bulk delete or export activities
