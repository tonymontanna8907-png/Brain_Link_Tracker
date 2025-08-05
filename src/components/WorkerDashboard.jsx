import React, { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { toast } from 'sonner';
import { 
  HardHat, Eye, BarChart3, TrendingUp, Activity, 
  Link, Mail, Calendar, Globe, Copy, ExternalLink,
  Target, Users, MousePointer, Shield, AlertCircle
} from 'lucide-react';

const WorkerDashboard = ({ user, token }) => {
  const [assignedCampaigns, setAssignedCampaigns] = useState([]);
  const [trackingLinks, setTrackingLinks] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAssignedCampaigns();
    fetchTrackingLinks();
    fetchAnalytics();
  }, []);

  const fetchAssignedCampaigns = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/worker/campaigns', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setAssignedCampaigns(data.campaigns || []);
      } else {
        toast.error('Failed to fetch assigned campaigns');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const fetchTrackingLinks = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/worker/tracking-links', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setTrackingLinks(data.links || []);
      } else {
        toast.error('Failed to fetch tracking links');
      }
    } catch (error) {
      toast.error('Network error');
    } finally {
      setLoading(false);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/worker/analytics', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setAnalytics(data);
      }
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const getStatusBadgeColor = (status) => {
    switch (status) {
      case 'sent': return 'bg-blue-500';
      case 'clicked': return 'bg-green-500';
      case 'opened': return 'bg-yellow-500';
      case 'redirected': return 'bg-purple-500';
      case 'ok': return 'bg-green-600';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'sent': return <Mail className="h-3 w-3" />;
      case 'clicked': return <MousePointer className="h-3 w-3" />;
      case 'opened': return <Eye className="h-3 w-3" />;
      case 'redirected': return <ExternalLink className="h-3 w-3" />;
      case 'ok': return <Target className="h-3 w-3" />;
      default: return <Activity className="h-3 w-3" />;
    }
  };

  // Calculate worker-specific statistics
  const workerStats = {
    totalLinks: trackingLinks.length,
    totalClicks: trackingLinks.reduce((sum, link) => sum + (link.clicks || 0), 0),
    totalOpens: trackingLinks.reduce((sum, link) => sum + (link.opens || 0), 0),
    activeCampaigns: assignedCampaigns.filter(c => c.status === 'active').length
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Worker Dashboard</h2>
          <p className="text-muted-foreground">View assigned campaigns and track performance</p>
        </div>
        <Badge className="bg-green-500 text-white">
          <HardHat className="h-3 w-3 mr-1" />
          Worker - Employee Access
        </Badge>
      </div>

      {/* Overview Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Assigned Campaigns</p>
                <p className="text-2xl font-bold">{workerStats.activeCampaigns}</p>
                <p className="text-xs text-gray-500">Active campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Link className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium">My Links</p>
                <p className="text-2xl font-bold">{workerStats.totalLinks}</p>
                <p className="text-xs text-gray-500">Links I can access</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <TrendingUp className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-sm font-medium">Total Clicks</p>
                <p className="text-2xl font-bold">{workerStats.totalClicks}</p>
                <p className="text-xs text-gray-500">From my campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Activity className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-sm font-medium">Email Opens</p>
                <p className="text-2xl font-bold">{workerStats.totalOpens}</p>
                <p className="text-xs text-gray-500">Total opens</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Assigned Campaigns */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Target className="h-5 w-5" />
            <span>Assigned Campaigns</span>
          </CardTitle>
          <CardDescription>
            Campaigns you have been assigned to work on
          </CardDescription>
        </CardHeader>
        <CardContent>
          {assignedCampaigns.length === 0 ? (
            <div className="text-center py-8">
              <Target className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No campaigns assigned yet. Contact your manager for access.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {assignedCampaigns.map((campaign) => {
                const campaignLinks = trackingLinks.filter(link => link.campaign_id === campaign.id);
                const campaignClicks = campaignLinks.reduce((sum, link) => sum + (link.clicks || 0), 0);
                const campaignOpens = campaignLinks.reduce((sum, link) => sum + (link.opens || 0), 0);
                
                return (
                  <Card key={campaign.id} className="border-l-4 border-l-green-500">
                    <CardContent className="p-4">
                      <div className="space-y-3">
                        <div>
                          <h4 className="font-semibold">{campaign.name}</h4>
                          <p className="text-sm text-gray-500">{campaign.description || 'No description'}</p>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div>
                            <span className="text-gray-500">Links:</span>
                            <span className="ml-1 font-medium">{campaignLinks.length}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Clicks:</span>
                            <span className="ml-1 font-medium">{campaignClicks}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Opens:</span>
                            <span className="ml-1 font-medium">{campaignOpens}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Status:</span>
                            <Badge 
                              variant="outline" 
                              className={`ml-1 ${campaign.status === 'active' ? 'text-green-600' : 'text-gray-600'}`}
                            >
                              {campaign.status}
                            </Badge>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <Badge variant="outline">
                            {new Date(campaign.created_at).toLocaleDateString()}
                          </Badge>
                          <Badge className="bg-green-100 text-green-800">
                            Assigned
                          </Badge>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Tracking Links (Read-Only) */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Link className="h-5 w-5" />
            <span>Campaign Tracking Links</span>
          </CardTitle>
          <CardDescription>
            View tracking links from your assigned campaigns (Read-only access)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {trackingLinks.length === 0 ? (
            <div className="text-center py-8">
              <Link className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No tracking links available in your assigned campaigns.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Campaign</TableHead>
                  <TableHead>Original URL</TableHead>
                  <TableHead>Tracking Link</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Clicks</TableHead>
                  <TableHead>Opens</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {trackingLinks.map((link) => {
                  const campaign = assignedCampaigns.find(c => c.id === link.campaign_id);
                  const trackingUrl = `https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/track/click/${link.tracking_token}`;
                  
                  return (
                    <TableRow key={link.id}>
                      <TableCell>
                        <Badge variant="outline">
                          {campaign ? campaign.name : 'Unknown'}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">
                        <a 
                          href={link.original_url} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:underline"
                        >
                          {link.original_url}
                        </a>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <div className="flex items-center space-x-2">
                          <span className="truncate text-sm font-mono">
                            {trackingUrl}
                          </span>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyToClipboard(trackingUrl)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusBadgeColor(link.link_status)} text-white`}>
                          <div className="flex items-center space-x-1">
                            {getStatusIcon(link.link_status)}
                            <span className="capitalize">{link.link_status}</span>
                          </div>
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{link.clicks || 0}</span>
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{link.opens || 0}</span>
                      </TableCell>
                      <TableCell>
                        {new Date(link.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(trackingUrl)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => window.open(link.original_url, '_blank')}
                          >
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Worker Access Restrictions */}
      <Card className="border-green-200 bg-green-50">
        <CardContent className="p-4">
          <div className="flex items-start space-x-3">
            <HardHat className="h-5 w-5 text-green-600 mt-0.5" />
            <div>
              <h4 className="font-medium text-green-800">Worker Access Level</h4>
              <p className="text-sm text-green-700 mt-1">
                As a Worker, you have limited access to assigned campaigns only:
              </p>
              <ul className="text-sm text-green-700 mt-2 space-y-1">
                <li>• View campaigns assigned to you by your manager</li>
                <li>• Read-only access to tracking links and analytics</li>
                <li>• Cannot create, edit, or delete campaigns or links</li>
                <li>• Can copy tracking links for use in your work</li>
                <li>• Monitor performance of campaigns you're working on</li>
                <li>• Contact your manager for additional access or assignments</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Performance Summary */}
      {analytics && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <BarChart3 className="h-5 w-5" />
              <span>My Performance Summary</span>
            </CardTitle>
            <CardDescription>
              Your contribution to assigned campaigns
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">{workerStats.totalLinks}</div>
                <div className="text-sm text-blue-800">Links Accessible</div>
              </div>
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">{workerStats.totalClicks}</div>
                <div className="text-sm text-green-800">Total Clicks Generated</div>
              </div>
              <div className="text-center p-4 bg-purple-50 rounded-lg">
                <div className="text-2xl font-bold text-purple-600">
                  {workerStats.totalClicks > 0 ? ((workerStats.totalOpens / workerStats.totalClicks) * 100).toFixed(1) : 0}%
                </div>
                <div className="text-sm text-purple-800">Open Rate</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default WorkerDashboard;

