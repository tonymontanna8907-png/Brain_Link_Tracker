import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { 
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { 
  Link, Plus, Copy, Eye, MousePointer, Mail, 
  ExternalLink, Calendar, Globe, Activity,
  RefreshCw, Search, Filter
} from 'lucide-react'
import { toast } from 'sonner'
import { API_ENDPOINTS } from '../config'

const TrackingLinksPage = () => {
  const [trackingLinks, setTrackingLinks] = useState([])
  const [loading, setLoading] = useState(true)
  const [newUrl, setNewUrl] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [newCampaign, setNewCampaign] = useState('')
  const [creating, setCreating] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  // Get auth token from localStorage
  const getAuthToken = () => localStorage.getItem('authToken')

  // Fetch tracking links from API
  const fetchTrackingLinks = async () => {
    try {
      setLoading(true)
      const response = await fetch(API_ENDPOINTS.LINKS, {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`,
          'Content-Type': 'application/json'
        }
      })
      const data = await response.json()
      
      if (response.ok) {
        setTrackingLinks(data.tracking_links || [])
      } else {
        toast.error(data.error || 'Failed to load tracking links')
      }
    } catch (error) {
      console.error('Error fetching tracking links:', error)
      toast.error('Failed to load tracking links')
    } finally {
      setLoading(false)
    }
  }

  // Create new tracking link
  const createTrackingLink = async () => {
    if (!newUrl.trim()) {
      toast.error('Please enter a URL')
      return
    }

    try {
      setCreating(true)
      const response = await fetch(API_ENDPOINTS.LINKS, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          original_url: newUrl,
          recipient_email: newEmail,
          recipient_name: newCampaign || 'Default Campaign'
        })
      })

      const data = await response.json()
      
      if (response.ok) {
        toast.success('Tracking link created successfully!')
        setNewUrl('')
        setNewEmail('')
        setNewCampaign('')
        fetchTrackingLinks() // Refresh the list
      } else {
        toast.error(data.error || 'Failed to create tracking link')
      }
    } catch (error) {
      console.error('Error creating tracking link:', error)
      toast.error('Failed to create tracking link')
    } finally {
      setCreating(false)
    }
  }

  // Copy to clipboard
  const copyToClipboard = async (text, type) => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success(`${type} copied to clipboard!`)
    } catch (error) {
      toast.error('Failed to copy to clipboard')
    }
  }

  // Format date
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString()
  }

  // Filter tracking links based on search term
  const filteredLinks = trackingLinks.filter(link =>
    link.original_url.toLowerCase().includes(searchTerm.toLowerCase()) ||
    link.recipient_email.toLowerCase().includes(searchTerm.toLowerCase()) ||
    link.campaign_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    link.tracking_token.toLowerCase().includes(searchTerm.toLowerCase())
  )

  useEffect(() => {
    fetchTrackingLinks()
  }, [])

  return (
    <div className="space-y-6">
      {/* URL Generator Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Plus className="h-5 w-5" />
            <span>Generate New Tracking Link</span>
          </CardTitle>
          <CardDescription>
            Create a new tracking link for your campaign. Enter your original URL and get a protected tracking link that blocks bots and provides analytics.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <Input
                placeholder="Enter your campaign URL (e.g., https://example.com)"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                className="w-full"
              />
            </div>
            <div>
              <Input
                placeholder="Recipient email (optional)"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                className="w-full"
              />
            </div>
            <div>
              <Input
                placeholder="Campaign name (optional)"
                value={newCampaign}
                onChange={(e) => setNewCampaign(e.target.value)}
                className="w-full"
              />
            </div>
          </div>
          <div className="flex justify-between items-center mt-4">
            <div className="text-sm text-muted-foreground">
              Your tracking link will be protected against bots, social media crawlers, and security scanners.
            </div>
            <Button 
              onClick={createTrackingLink} 
              disabled={creating || !newUrl.trim()}
              className="ml-4"
            >
              {creating ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Creating...
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4 mr-2" />
                  Generate Link
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tracking Links Table */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Link className="h-5 w-5" />
                <span>Tracking Links</span>
              </CardTitle>
              <CardDescription>
                Manage and monitor all your tracking links
              </CardDescription>
            </div>
            <div className="flex space-x-2">
              <div className="relative">
                <Search className="h-4 w-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search links..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9 w-64"
                />
              </div>
              <Button variant="outline" onClick={fetchTrackingLinks}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center items-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin mr-2" />
              Loading tracking links...
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Tracking ID</TableHead>
                    <TableHead>Original URL</TableHead>
                    <TableHead>Campaign</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Stats</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLinks.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                        {searchTerm ? 'No tracking links match your search.' : 'No tracking links found. Create your first tracking link above.'}
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredLinks.map((link) => (
                      <TableRow key={link.id}>
                        <TableCell className="font-mono text-sm">
                          {link.tracking_token}
                        </TableCell>
                        <TableCell>
                          <div className="max-w-xs truncate" title={link.original_url}>
                            {link.original_url}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{link.campaign_name}</Badge>
                        </TableCell>
                        <TableCell>{link.recipient_email}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {formatDate(link.created_at)}
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-4 text-sm">
                            <div className="flex items-center space-x-1">
                              <MousePointer className="h-3 w-3 text-blue-500" />
                              <span>{link.clicks}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Mail className="h-3 w-3 text-green-500" />
                              <span>{link.opens}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Activity className="h-3 w-3 text-purple-500" />
                              <span>{link.total_events}</span>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={link.is_active ? "default" : "secondary"}>
                            {link.is_active ? "Active" : "Inactive"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(link.tracking_url, 'Tracking URL')}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(link.pixel_url, 'Pixel URL')}
                            >
                              <Eye className="h-3 w-3" />
                            </Button>
                            <Dialog>
                              <DialogTrigger asChild>
                                <Button variant="outline" size="sm">
                                  <ExternalLink className="h-3 w-3" />
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="max-w-2xl">
                                <DialogHeader>
                                  <DialogTitle>Tracking Link Details</DialogTitle>
                                  <DialogDescription>
                                    Complete information for tracking link {link.tracking_token}
                                  </DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4">
                                  <div>
                                    <label className="text-sm font-medium">Tracking URL (for links)</label>
                                    <div className="flex items-center space-x-2 mt-1">
                                      <Input value={link.tracking_url} readOnly className="font-mono text-sm" />
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => copyToClipboard(link.tracking_url, 'Tracking URL')}
                                      >
                                        <Copy className="h-4 w-4" />
                                      </Button>
                                    </div>
                                  </div>
                                  <div>
                                    <label className="text-sm font-medium">Pixel URL (for emails)</label>
                                    <div className="flex items-center space-x-2 mt-1">
                                      <Input value={link.pixel_url} readOnly className="font-mono text-sm" />
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => copyToClipboard(link.pixel_url, 'Pixel URL')}
                                      >
                                        <Copy className="h-4 w-4" />
                                      </Button>
                                    </div>
                                  </div>
                                  <div>
                                    <label className="text-sm font-medium">Email Tracking Code</label>
                                    <div className="flex items-center space-x-2 mt-1">
                                      <Input 
                                        value={`<img src="${link.pixel_url}" width="1" height="1" style="display:none;" />`} 
                                        readOnly 
                                        className="font-mono text-sm" 
                                      />
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => copyToClipboard(`<img src="${link.pixel_url}" width="1" height="1" style="display:none;" />`, 'Email tracking code')}
                                      >
                                        <Copy className="h-4 w-4" />
                                      </Button>
                                    </div>
                                  </div>
                                </div>
                              </DialogContent>
                            </Dialog>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <Link className="h-4 w-4 text-blue-500" />
              <div className="text-2xl font-bold">{trackingLinks.length}</div>
            </div>
            <p className="text-xs text-muted-foreground mt-1">Total Links</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <MousePointer className="h-4 w-4 text-green-500" />
              <div className="text-2xl font-bold">
                {trackingLinks.reduce((sum, link) => sum + link.clicks, 0)}
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-1">Total Clicks</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <Mail className="h-4 w-4 text-purple-500" />
              <div className="text-2xl font-bold">
                {trackingLinks.reduce((sum, link) => sum + link.opens, 0)}
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-1">Total Opens</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <Activity className="h-4 w-4 text-orange-500" />
              <div className="text-2xl font-bold">
                {trackingLinks.filter(link => link.is_active).length}
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-1">Active Links</p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default TrackingLinksPage

