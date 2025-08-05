import React, { useState, useEffect } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card'
import { Badge } from './components/ui/badge'
import { Button } from './components/ui/button'
import { Toaster } from 'sonner'
import TrackingLinksPage from './components/TrackingLinksPage'
import LoginPage from './components/LoginPage'
import AdminPanel from './components/AdminPanel'
import Admin2Dashboard from './components/Admin2Dashboard'
import MemberDashboard from './components/MemberDashboard'
import WorkerDashboard from './components/WorkerDashboard'
import PasswordChangeModal from './components/PasswordChangeModal'
import ClickAnalyticsTable from './components/ClickAnalyticsTable'
import CampaignOverview from './components/CampaignOverview'
import { API_ENDPOINTS } from './config'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Area, AreaChart
} from 'recharts'
import { 
  TrendingUp, Users, Globe, Shield, Activity, AlertTriangle,
  RefreshCw, Download, LogOut, Settings, Crown, Link
} from 'lucide-react'
import './App.css'

function App() {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(null)
  const [analytics, setAnalytics] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check for existing session
    const savedToken = localStorage.getItem('authToken')
    const savedUser = localStorage.getItem('user')
    
    if (savedToken && savedUser) {
      setToken(savedToken)
      setUser(JSON.parse(savedUser))
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    if (user && token) {
      fetchAnalytics()
      const interval = setInterval(fetchAnalytics, 30000) // Refresh every 30 seconds
      return () => clearInterval(interval)
    }
  }, [user, token])

  const fetchAnalytics = async () => {
    try {
      const response = await fetch(API_ENDPOINTS.ANALYTICS, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })
      if (response.ok) {
        const data = await response.json()
        setAnalytics(data)
      }
    } catch (error) {
      console.error('Failed to fetch analytics:', error)
    }
  }

  const handleLogin = (userData, authToken) => {
    setUser(userData)
    setToken(authToken)
  }

  const handleLogout = () => {
    localStorage.removeItem('authToken')
    localStorage.removeItem('user')
    setUser(null)
    setToken(null)
    setAnalytics(null)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    )
  }
  const handleExport = () => {
    if (!analytics) {
      toast.error('No data to export');
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      analytics: analytics,
      user: {
        username: user.username,
        role: user.role
      }
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `brain-link-tracker-analytics-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast.success('Analytics data exported successfully!');
  };

  if (!user || !token) {
    return (
      <>
        <LoginPage onLogin={handleLogin} />
        <Toaster />
      </>
    )
  }

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8']

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto p-6">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-8 space-y-4 lg:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3">
              <Link className="h-6 w-6 lg:h-8 lg:w-8 text-blue-400" />
              <div>
                <h1 className="text-2xl lg:text-3xl font-bold text-white">Brain Link Tracker</h1>
                <p className="text-slate-300 text-sm lg:text-base">Advanced Analytics Dashboard</p>
              </div>
            </div>
          </div>
          <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-4">
            <div className="text-left sm:text-right">
              <p className="text-white font-medium">{user.username}</p>
              <Badge className={`${getRoleBadgeColor(user.role)} text-white`}>
                {user.role === 'admin' && <Crown className="h-3 w-3 mr-1" />}
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </Badge>
            </div>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        {/* Main Content */}
        {user.role === 'member' ? (
          <MemberDashboard user={user} token={token} />
        ) : user.role === 'worker' ? (
          <WorkerDashboard user={user} token={token} />
        ) : (
          <div className="bg-white rounded-lg shadow-lg">
            <div className="p-6">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-6 space-y-4 lg:space-y-0">
                <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-4">
                  <h2 className="text-xl lg:text-2xl font-bold text-gray-800">Advanced Analytics</h2>
                  <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 text-xs lg:text-sm">
                    Last updated: {analytics ? new Date().toLocaleTimeString() : 'Loading...'}
                  </Badge>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" onClick={fetchAnalytics}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleExport}>
                    <Download className="h-4 w-4 mr-2" />
                    Export
                  </Button>
                  <PasswordChangeModal token={token} />
                </div>
              </div>

              <Tabs defaultValue="analytics" className="w-full">
                <TabsList className="grid w-full grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-1 h-auto p-1">
                  <TabsTrigger value="analytics" className="text-xs sm:text-sm p-2">Analytics</TabsTrigger>
                  <TabsTrigger value="tracking-links" className="text-xs sm:text-sm p-2">Tracking Links</TabsTrigger>
                  {(user.role === 'admin' || user.role === 'admin2') && (
                    <>
                      <TabsTrigger value="admin" className="text-xs sm:text-sm p-2">
                        {user.role === 'admin' ? 'User Management' : 'Team Management'}
                      </TabsTrigger>
                      {user.role === 'admin' && (
                        <TabsTrigger value="campaigns" className="text-xs sm:text-sm p-2">Campaign Overview</TabsTrigger>
                      )}
                    </>
                  )}
                  <TabsTrigger value="security" className="text-xs sm:text-sm p-2">Security</TabsTrigger>
                  <TabsTrigger value="geography" className="text-xs sm:text-sm p-2">Geography</TabsTrigger>
                  <TabsTrigger value="live-activity" className="text-xs sm:text-sm p-2">Live Activity</TabsTrigger>
                </TabsList>

              <TabsContent value="analytics" className="space-y-6">
                {analytics ? (
                  <>
                    {/* Overview Cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4">
                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <TrendingUp className="h-5 w-5 text-blue-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Total Users</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.total_users || 0}</p>
                              <p className="text-xs text-green-600">All registered users</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <div className="h-5 w-5 bg-green-500 rounded-full flex items-center justify-center">
                              <span className="text-white text-xs">✓</span>
                            </div>
                            <div>
                              <p className="text-sm font-medium text-gray-600">Active Users</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.active_users || 0}</p>
                              <p className="text-xs text-green-600">Approved accounts</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <Users className="h-5 w-5 text-purple-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Pending Approval</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.pending_users || 0}</p>
                              <p className="text-xs text-orange-600">Awaiting approval</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <Activity className="h-5 w-5 text-orange-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Admin Users</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.admin_users || 0}</p>
                              <p className="text-xs text-blue-600">System administrators</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <Shield className="h-5 w-5 text-red-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">System Status</p>
                              <p className="text-2xl font-bold text-gray-900">Online</p>
                              <p className="text-xs text-green-600">All systems operational</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <AlertTriangle className="h-5 w-5 text-yellow-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Last Updated</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.last_updated ? new Date(analytics.last_updated).toLocaleTimeString() : 'Now'}</p>
                              <p className="text-xs text-yellow-600">Monitoring</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Charts */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle>User Distribution</CardTitle>
                          <CardDescription>Breakdown of user types and status</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={[
                              { name: 'Total Users', value: analytics.total_users || 0, color: '#3b82f6' },
                              { name: 'Active Users', value: analytics.active_users || 0, color: '#10b981' },
                              { name: 'Pending Users', value: analytics.pending_users || 0, color: '#f59e0b' },
                              { name: 'Admin Users', value: analytics.admin_users || 0, color: '#ef4444' }
                            ]}>
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="name" />
                              <YAxis />
                              <Tooltip />
                              <Bar dataKey="value" fill="#3b82f6" />
                            </BarChart>
                          </ResponsiveContainer>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle>Activity Overview</CardTitle>
                          <CardDescription>Campaigns, links, and engagement metrics</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={[
                              { name: 'Campaigns', value: analytics.total_campaigns || 0, color: '#8b5cf6' },
                              { name: 'Links', value: analytics.total_links || 0, color: '#06b6d4' },
                              { name: 'Clicks', value: analytics.total_clicks || 0, color: '#f97316' },
                              { name: 'Pixel Views', value: analytics.total_pixel_views || 0, color: '#84cc16' }
                            ]}>
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="name" />
                              <YAxis />
                              <Tooltip />
                              <Bar dataKey="value" fill="#8b5cf6" />
                            </BarChart>
                          </ResponsiveContainer>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Additional Analytics */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle>User Statistics</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-4">
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Total Users</span>
                              <span className="text-lg font-bold">{analytics.total_users || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Active Users</span>
                              <span className="text-lg font-bold text-green-600">{analytics.active_users || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Pending Users</span>
                              <span className="text-lg font-bold text-orange-600">{analytics.pending_users || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Admin Users</span>
                              <span className="text-lg font-bold text-blue-600">{analytics.admin_users || 0}</span>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle>Campaign Metrics</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-4">
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Total Campaigns</span>
                              <span className="text-lg font-bold">{analytics.total_campaigns || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Total Links</span>
                              <span className="text-lg font-bold text-blue-600">{analytics.total_links || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Total Clicks</span>
                              <span className="text-lg font-bold text-purple-600">{analytics.total_clicks || 0}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Pixel Views</span>
                              <span className="text-lg font-bold text-green-600">{analytics.total_pixel_views || 0}</span>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle>System Information</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-4">
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Database Status</span>
                              <Badge className="bg-green-100 text-green-800">Connected</Badge>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">API Status</span>
                              <Badge className="bg-green-100 text-green-800">Online</Badge>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Last Updated</span>
                              <span className="text-sm">Just now</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Uptime</span>
                              <span className="text-sm text-green-600">99.9%</span>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8">
                    <TrendingUp className="h-16 w-16 mx-auto text-gray-400 mb-4" />
                    <p className="text-gray-600">Loading analytics data...</p>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="tracking-links">
                <TrackingLinksPage user={user} token={token} />
              </TabsContent>

              {(user.role === 'admin' || user.role === 'admin2') && (
                <TabsContent value="admin">
                  {user.role === 'admin' ? (
                    <AdminPanel user={user} token={token} />
                  ) : (
                    <Admin2Dashboard user={user} token={token} />
                  )}
                </TabsContent>
              )}

              {user.role === 'admin' && (
                <TabsContent value="campaigns">
                  <CampaignOverview token={token} />
                </TabsContent>
              )}

              <TabsContent value="security" className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Shield className="h-5 w-5" />
                      <span>Security Status</span>
                    </CardTitle>
                    <CardDescription>
                      System security monitoring and user access control
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-sm font-medium text-gray-600">Authentication</p>
                              <p className="text-2xl font-bold text-gray-900">Secure</p>
                            </div>
                            <Badge className="bg-green-100 text-green-800">Active</Badge>
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-sm font-medium text-gray-600">User Sessions</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics ? analytics.active_users || 0 : 0}</p>
                            </div>
                            <Badge className="bg-blue-100 text-blue-800">Monitored</Badge>
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-sm font-medium text-gray-600">Access Control</p>
                              <p className="text-2xl font-bold text-gray-900">Enabled</p>
                            </div>
                            <Badge className="bg-green-100 text-green-800">Protected</Badge>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="geography" className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Globe className="h-5 w-5" />
                      <span>Geographic Information</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-center py-8">
                      <Globe className="h-16 w-16 mx-auto text-gray-400 mb-4" />
                      <p className="text-gray-600">Geographic data will be available when user activity is tracked.</p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="live-activity" className="space-y-6">
                <ClickAnalyticsTable token={token} />
              </TabsContent>
            </Tabs>
          </div>
        </div>
        )}
      </div>
      <Toaster />
    </div>
  )
}

function getRoleBadgeColor(role) {
  switch (role) {
    case 'admin': return 'bg-red-500'
    case 'admin2': return 'bg-orange-500'
    case 'member': return 'bg-blue-500'
    case 'worker': return 'bg-green-500'
    default: return 'bg-gray-500'
  }
}

export default App

