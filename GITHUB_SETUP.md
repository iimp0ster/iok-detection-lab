# GitHub Repository Setup Guide

## How to Create Your GitHub Repository

### Step 1: Create Repository on GitHub

1. Go to https://github.com/new
2. Repository name: `iok-detection-lab` (or your preferred name)
3. Description: "Automated phishing detection using IOK rules with SIEM integration"
4. Choose: **Public** (to share) or **Private**
5. **DO NOT** initialize with README, .gitignore, or license (we already have them)
6. Click "Create repository"

### Step 2: Upload Your Files

**Option A: Using Git (Recommended)**

```bash
# Navigate to the downloaded directory
cd iok-detection-lab

# Initialize git repository
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: IOK detection lab with SIEM integration"

# Add your GitHub repository as remote
git remote add origin https://github.com/YOUR_USERNAME/iok-detection-lab.git

# Push to GitHub
git branch -M main
git push -u origin main
```

**Option B: GitHub Desktop**

1. Download [GitHub Desktop](https://desktop.github.com/)
2. File → Add Local Repository
3. Choose the `iok-detection-lab` folder
4. Publish repository to GitHub

**Option C: Upload via Web Interface**

1. Go to your new repository on GitHub
2. Click "uploading an existing file"
3. Drag and drop all files
4. Commit changes

### Step 3: Verify Upload

Go to your repository URL:
```
https://github.com/YOUR_USERNAME/iok-detection-lab
```

You should see:
- ✅ README.md displaying with formatting
- ✅ All folders (docs/, scripts/, siem-integration/)
- ✅ LICENSE and .gitignore files

### Step 4: Clone from Any Machine

Now anyone (including you from other machines) can install:

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab

# Run setup
chmod +x setup.sh
./setup.sh

# Start using
source venv/bin/activate
python3 scripts/iok_collector.py https://example.com
```

## Installation from GitHub (For Users)

### Quick Install

```bash
# One-liner install
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git && \
cd iok-detection-lab && \
chmod +x setup.sh && \
./setup.sh
```

### Step-by-Step Install

```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab

# 2. Run setup script
chmod +x setup.sh
./setup.sh

# 3. Activate Python environment
source venv/bin/activate

# 4. Test installation
python3 scripts/iok_collector.py https://example.com
python3 scripts/iok_detector.py iok_event.json IOK/indicators/
```

## Updating Your Repository

### Add New Features

```bash
# Make your changes
nano scripts/new_feature.py

# Stage changes
git add .

# Commit with descriptive message
git commit -m "Add new feature: batch processing improvements"

# Push to GitHub
git push origin main
```

### Update IOK Rules

```bash
# Update the IOK submodule
cd IOK
git pull
cd ..

# Commit the update
git add IOK
git commit -m "Update IOK rules to latest version"
git push origin main
```

### Pull Latest Changes

```bash
# On another machine, get latest version
git pull origin main

# Update IOK rules
cd IOK && git pull && cd ..
```

## Sharing Your Repository

### Make it Public

1. Go to repository Settings
2. Scroll to "Danger Zone"
3. Click "Change visibility"
4. Choose "Make public"

### Share Installation Instructions

Send users this link:
```
https://github.com/YOUR_USERNAME/iok-detection-lab
```

They can install with:
```bash
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab
./setup.sh
```

### Add Topics/Tags

Make your repo discoverable:

1. Click ⚙️ (gear icon) next to "About" on repo homepage
2. Add topics:
   - `phishing-detection`
   - `iok`
   - `sigma-rules`
   - `threat-intelligence`
   - `security-operations`
   - `detection-engineering`
   - `splunk`
   - `elasticsearch`

## Advanced: Using GitHub Releases

### Create a Release

```bash
# Tag a version
git tag -a v1.0.0 -m "Initial release"
git push origin v1.0.0
```

Then on GitHub:
1. Go to "Releases"
2. Click "Create a new release"
3. Choose your tag (v1.0.0)
4. Add release notes
5. Publish release

Users can then download specific versions:
```bash
git clone --branch v1.0.0 https://github.com/YOUR_USERNAME/iok-detection-lab.git
```

## Repository Structure

```
iok-detection-lab/
├── README.md                 # Main documentation (auto-displayed)
├── LICENSE                   # MIT license
├── .gitignore               # Files to exclude from git
├── setup.sh                 # Installation script
├── requirements.txt         # Python dependencies
├── urls.txt                 # Example URL list
├── scripts/                 # Core Python scripts
│   ├── iok_collector.py
│   ├── iok_detector.py
│   └── iok_batch.py
├── siem-integration/        # SIEM integration components
│   ├── iok_api.py
│   ├── splunk_iok_action.py
│   ├── elastic_iok_enrich.py
│   └── elastic_watcher_iok.json
└── docs/                    # Documentation
    ├── SETUP_INSTRUCTIONS.md
    ├── SIEM_INTEGRATION.md
    ├── DEPLOYMENT_CHECKLIST.md
    └── QUICK_REFERENCE.md
```

## Troubleshooting Git Issues

### Authentication Issues

**If using HTTPS:**
```bash
# Use personal access token instead of password
# Generate at: https://github.com/settings/tokens
git remote set-url origin https://YOUR_USERNAME:YOUR_TOKEN@github.com/YOUR_USERNAME/iok-detection-lab.git
```

**Or use SSH:**
```bash
# Generate SSH key (if needed)
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to GitHub: https://github.com/settings/keys

# Change remote to SSH
git remote set-url origin git@github.com:YOUR_USERNAME/iok-detection-lab.git
```

### Large Files

GitHub has 100MB file size limit. If you hit this:

```bash
# Check file sizes
du -sh * | sort -h

# Remove large files from tracking
git rm --cached large_file.bin
echo "large_file.bin" >> .gitignore
```

### Accidental Commit of Sensitive Data

```bash
# Remove from history (use carefully!)
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/sensitive_file" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (only if repo is yours alone)
git push origin --force --all
```

## Example: Complete Setup Flow

```bash
# 1. Download the files (from Claude.ai)
# 2. Open terminal in the iok-detection-lab directory

# 3. Initialize git
git init
git add .
git commit -m "Initial commit"

# 4. Create repo on GitHub (via web interface)
# 5. Link and push
git remote add origin https://github.com/YOUR_USERNAME/iok-detection-lab.git
git branch -M main
git push -u origin main

# 6. Done! Verify at:
# https://github.com/YOUR_USERNAME/iok-detection-lab
```

## Collaborating with Others

### Fork Workflow

1. Others fork your repository
2. Make changes in their fork
3. Submit Pull Request
4. You review and merge

### Branch Protection

1. Settings → Branches
2. Add rule for `main`
3. Enable:
   - Require pull request reviews
   - Require status checks

## Next Steps

After creating your GitHub repository:

1. ✅ Verify all files uploaded correctly
2. ✅ Test `git clone` from another directory
3. ✅ Run `./setup.sh` to ensure it works
4. ✅ Update README.md with your username
5. ✅ Add topics/tags for discoverability
6. ✅ Share with your team!

---

**Questions?** Open an issue on GitHub or check the docs/ folder.
