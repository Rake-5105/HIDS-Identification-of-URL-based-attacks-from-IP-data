import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Activity, 
  Database, 
  Search, 
  BarChart3, 
  Brain,
  FileText,
  Cpu,
  Eye,
  ArrowRight,
  Github,
  Mail,
  Linkedin,
  ChevronDown,
  Network,
  Lock,
  Zap,
  Menu,
  X
} from 'lucide-react';
import { ContainerScroll } from '../components/ContainerScroll';
import { SplineScene } from '../components/SplineScene';

// Typing Animation Component
const TypeWriter = ({ text, delay = 100 }) => {
  const [displayText, setDisplayText] = useState('');
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    if (currentIndex < text.length) {
      const timeout = setTimeout(() => {
        setDisplayText(prev => prev + text[currentIndex]);
        setCurrentIndex(prev => prev + 1);
      }, delay);
      return () => clearTimeout(timeout);
    }
  }, [currentIndex, text, delay]);

  return (
    <span>
      {displayText}
      <span className="animate-pulse">|</span>
    </span>
  );
};

// Floating Particles Background
const ParticlesBackground = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {[...Array(50)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-1 h-1 bg-cyan-500/30 rounded-full"
          initial={{
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
          }}
          animate={{
            y: [null, Math.random() * -500],
            opacity: [0, 1, 0],
          }}
          transition={{
            duration: Math.random() * 10 + 10,
            repeat: Infinity,
            ease: "linear",
          }}
        />
      ))}
    </div>
  );
};

// Cyber Grid Background
const CyberGrid = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-20">
      <div 
        className="absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 255, 255, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 255, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
          animation: 'gridMove 20s linear infinite',
        }}
      />
    </div>
  );
};

// Navbar Component
const Navbar = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { name: 'Features', href: '#features' },
    { name: 'How It Works', href: '#how-it-works' },
    { name: 'Preview', href: '#preview' },
    { name: 'About', href: '#about' },
  ];

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled 
          ? 'bg-gray-900/90 backdrop-blur-xl border-b border-cyan-500/20' 
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <span className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-500 bg-clip-text text-transparent">
              HIDS
            </span>
          </Link>

          {/* Desktop Nav Links */}
          <div className="hidden md:flex items-center space-x-8">
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                className="text-gray-300 hover:text-cyan-400 transition-colors duration-200 text-sm font-medium"
              >
                {link.name}
              </a>
            ))}
          </div>

          {/* CTA Buttons */}
          <div className="hidden md:flex items-center space-x-4">
            <Link
              to="/login"
              className="text-gray-300 hover:text-white transition-colors duration-200 text-sm font-medium"
            >
              Sign In
            </Link>
            <Link
              to="/register"
              className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-purple-600 text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity shadow-lg shadow-cyan-500/25"
            >
              Get Started
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="md:hidden p-2 text-gray-400 hover:text-white"
          >
            {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="md:hidden py-4 border-t border-gray-800"
          >
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                className="block py-2 text-gray-300 hover:text-cyan-400"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                {link.name}
              </a>
            ))}
            <div className="flex flex-col space-y-2 mt-4">
              <Link to="/login" className="text-gray-300 hover:text-white py-2">
                Sign In
              </Link>
              <Link
                to="/register"
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-purple-600 text-white rounded-lg text-center"
              >
                Get Started
              </Link>
            </div>
          </motion.div>
        )}
      </div>
    </motion.nav>
  );
};

// Hero Section
const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-gray-950">
      <CyberGrid />
      <ParticlesBackground />
      
      {/* Gradient Orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl" />
      
      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
          {/* Left Content */}
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            className="flex-1 text-center lg:text-left"
          >
            <div className="inline-flex items-center space-x-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-full mb-8">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span className="text-cyan-400 text-sm font-medium">AI-Powered Security Analysis</span>
            </div>
            
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-white mb-6 leading-tight">
              Advanced URL Attack
              <br />
              <span className="bg-gradient-to-r from-cyan-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
                Detection System
              </span>
            </h1>
            
            <p className="text-lg md:text-xl text-gray-400 mb-8 max-w-xl">
              Analyze, Detect, and Visualize Web-Based Threats in Real-Time using Hybrid ML Detection
            </p>
            
            <div className="flex flex-col sm:flex-row items-center lg:items-start justify-center lg:justify-start space-y-4 sm:space-y-0 sm:space-x-4">
              <Link
                to="/register"
                className="group px-8 py-4 bg-gradient-to-r from-cyan-500 to-purple-600 text-white rounded-xl text-lg font-semibold hover:opacity-90 transition-all shadow-2xl shadow-cyan-500/25 flex items-center space-x-2"
              >
                <span>Get Started</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </Link>
              <Link
                to="/login"
                className="px-8 py-4 bg-white/5 backdrop-blur-sm border border-white/10 text-white rounded-xl text-lg font-semibold hover:bg-white/10 transition-all flex items-center space-x-2"
              >
                <Eye className="w-5 h-5" />
                <span>View Dashboard</span>
              </Link>
            </div>
          </motion.div>

          {/* Right Content - 3D Spline */}
          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="flex-1 h-[400px] md:h-[500px] lg:h-[600px] w-full relative"
          >
            <SplineScene 
              scene="https://prod.spline.design/kZDDjO5HuC9GJUM2/scene.splinecode"
              className="w-full h-full"
            />
          </motion.div>
        </div>
        
        {/* Scroll Indicator */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1, duration: 1 }}
          className="absolute bottom-10 left-1/2 transform -translate-x-1/2"
        >
          <motion.div
            animate={{ y: [0, 10, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="flex flex-col items-center text-gray-500"
          >
            <span className="text-sm mb-2">Scroll to explore</span>
            <ChevronDown className="w-6 h-6" />
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
};

// Features Section
const FeaturesSection = () => {
  const features = [
    {
      icon: Database,
      title: "Log Collection",
      description: "Ingest HTTP logs, IPDR data, and PCAP files seamlessly",
      color: "cyan"
    },
    {
      icon: Search,
      title: "URL Parsing",
      description: "Extract IPs, timestamps, parameters, and status codes",
      color: "purple"
    },
    {
      icon: Activity,
      title: "Feature Analysis",
      description: "Detect anomalies, encoded payloads, and suspicious patterns",
      color: "pink"
    },
    {
      icon: Brain,
      title: "Hybrid Detection",
      description: "Combine rule-based and ML-powered threat detection",
      color: "green"
    },
    {
      icon: BarChart3,
      title: "Visualization",
      description: "Interactive dashboard with filters and trend analysis",
      color: "orange"
    },
  ];

  const colorClasses = {
    cyan: "from-cyan-500 to-cyan-600 shadow-cyan-500/25",
    purple: "from-purple-500 to-purple-600 shadow-purple-500/25",
    pink: "from-pink-500 to-pink-600 shadow-pink-500/25",
    green: "from-green-500 to-green-600 shadow-green-500/25",
    orange: "from-orange-500 to-orange-600 shadow-orange-500/25",
  };

  return (
    <section id="features" className="py-24 bg-gray-900 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-gray-950 to-gray-900" />
      
      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Powerful <span className="text-cyan-400">Features</span>
          </h2>
          <p className="text-gray-400 text-lg max-w-2xl mx-auto">
            Everything you need to detect and analyze URL-based attacks
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
              className="group relative p-6 bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-2xl hover:border-cyan-500/50 transition-all duration-300"
            >
              <div className={`inline-flex p-3 rounded-xl bg-gradient-to-br ${colorClasses[feature.color]} shadow-lg mb-4`}>
                <feature.icon className="w-6 h-6 text-white" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">{feature.title}</h3>
              <p className="text-gray-400">{feature.description}</p>
              
              {/* Glow effect on hover */}
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-cyan-500/0 via-cyan-500/5 to-purple-500/0 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

// How It Works Section
const HowItWorksSection = () => {
  const steps = [
    {
      step: "01",
      title: "Data Collection",
      description: "Upload HTTP logs, PCAP files, or CSV data from your network infrastructure",
      icon: FileText,
    },
    {
      step: "02",
      title: "Parsing & Extraction",
      description: "Automatically parse URLs and extract features like IPs, parameters, and timestamps",
      icon: Cpu,
    },
    {
      step: "03",
      title: "Detection & Classification",
      description: "Apply hybrid detection using rules and ML to identify attack types",
      icon: Brain,
    },
    {
      step: "04",
      title: "Visualization & Reporting",
      description: "View results on an interactive dashboard with filters and export options",
      icon: BarChart3,
    },
  ];

  return (
    <section id="how-it-works" className="py-24 bg-gray-950 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            How It <span className="text-purple-400">Works</span>
          </h2>
          <p className="text-gray-400 text-lg max-w-2xl mx-auto">
            From data ingestion to threat visualization in four simple steps
          </p>
        </motion.div>

        <div className="relative">
          {/* Connection Line */}
          <div className="hidden lg:block absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500 via-purple-500 to-pink-500 transform -translate-y-1/2" />
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {steps.map((item, index) => (
              <motion.div
                key={item.step}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.2 }}
                className="relative text-center"
              >
                <div className="relative z-10 mx-auto w-20 h-20 bg-gray-900 border-2 border-cyan-500/50 rounded-full flex items-center justify-center mb-6 shadow-lg shadow-cyan-500/20">
                  <item.icon className="w-8 h-8 text-cyan-400" />
                </div>
                <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-2 text-5xl font-bold text-gray-800">
                  {item.step}
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">{item.title}</h3>
                <p className="text-gray-400 text-sm">{item.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

// Dashboard Preview Section
const DashboardPreviewSection = () => {
  return (
    <section id="preview" className="bg-gray-950 relative overflow-hidden">
      <ContainerScroll
        titleComponent={
          <>
            <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
              Interactive <span className="text-cyan-400">Dashboard</span>
            </h2>
            <p className="text-gray-400 text-lg max-w-2xl mx-auto">
              Visualize attacks, filter by IP, and analyze trends in real-time
            </p>
          </>
        }
      >
        {/* Mock Dashboard Preview */}
        <div className="w-full h-full bg-gray-900 p-4 overflow-hidden">
          <div className="grid grid-cols-4 gap-4 mb-4">
            {['Total Requests', 'Attacks Detected', 'Safe Requests', 'Unique IPs'].map((label, i) => (
              <div key={label} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <p className="text-gray-400 text-xs">{label}</p>
                <p className="text-2xl font-bold text-white">{[1247, 342, 905, 89][i]}</p>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 h-48">
              <p className="text-gray-400 text-sm mb-2">Attack Distribution</p>
              <div className="flex items-end justify-around h-32">
                {[60, 80, 45, 90, 70].map((h, i) => (
                  <div
                    key={i}
                    className="w-8 bg-gradient-to-t from-cyan-500 to-purple-500 rounded-t"
                    style={{ height: `${h}%` }}
                  />
                ))}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 h-48">
              <p className="text-gray-400 text-sm mb-2">Attack Types</p>
              <div className="flex items-center justify-center h-32">
                <div className="relative w-32 h-32">
                  <svg viewBox="0 0 100 100" className="w-full h-full">
                    <circle cx="50" cy="50" r="40" fill="none" stroke="#06b6d4" strokeWidth="20" strokeDasharray="75 125" />
                    <circle cx="50" cy="50" r="40" fill="none" stroke="#a855f7" strokeWidth="20" strokeDasharray="50 150" strokeDashoffset="-75" />
                    <circle cx="50" cy="50" r="40" fill="none" stroke="#ec4899" strokeWidth="20" strokeDasharray="25 175" strokeDashoffset="-125" />
                  </svg>
                </div>
              </div>
            </div>
          </div>
        </div>
      </ContainerScroll>
    </section>
  );
};

// About Section
const AboutSection = () => {
  return (
    <section id="about" className="py-24 bg-gray-900 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="flex flex-col lg:flex-row items-stretch gap-12"
        >
          <div className="flex-1">
            <h2 className="text-3xl md:text-5xl font-bold text-white mb-6">
              About the <span className="text-pink-400">Project</span>
            </h2>
            <p className="text-gray-400 text-lg mb-6">
              This Hybrid-based Intrusion Detection System (HIDS) is designed as a comprehensive and efficient
              solution for identifying URL-based web attacks in modern web environments. By integrating
              traditional rule-based detection with advanced machine learning techniques, the system leverages
              the strengths of both approaches to deliver improved accuracy, adaptability, and real-time threat
              analysis. It is capable of detecting a wide range of attacks, including SQL Injection,
              Cross-Site Scripting (XSS), path traversal, and command injection, thereby addressing critical
              application-layer security concerns.
            </p>
            <p className="text-gray-400 text-lg mb-6">
              Developed with a strong focus on practical cybersecurity implementation and usability, this system
              emphasizes accessibility without compromising performance. The hybrid architecture enables faster
              detection of known threats while also adapting to emerging attack patterns through intelligent
              analysis. Additionally, the system provides interpretable results, allowing security analysts to
              understand detection decisions and respond effectively. Overall, this project highlights the
              effectiveness of hybrid intrusion detection approaches in building robust, scalable, and proactive
              web security solutions.
            </p>
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-gray-800 rounded-full">
                <Lock className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <p className="text-white font-semibold">Developed by</p>
                <p className="text-gray-400">Cyber Security Engineers</p>
              </div>
            </div>
          </div>
          <div className="flex-1 self-stretch">
            <div className="relative h-full">
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-purple-500 rounded-2xl blur-xl opacity-20" />
              <div className="relative h-full bg-gray-800 border border-gray-700 rounded-2xl p-8">
                <div className="flex h-full flex-col">
                  {[
                    { label: 'Attack Types', value: '15' },
                    { label: 'Detection Methods', value: 'Hybrid' },
                    { label: 'Real-time', value: 'Analysis' },
                    { label: 'Open Source', value: 'Project' },
                    { label: 'Better Visualization', value: 'Uses Chart Diagrams' },
                  ].map((stat, index, arr) => (
                    <div key={stat.label} className="contents">
                      <div className="text-center">
                        <p className="text-2xl font-bold text-cyan-400 leading-tight">{stat.value}</p>
                        <p className="text-gray-400 text-sm">{stat.label}</p>
                      </div>
                      {index < arr.length - 1 && (
                        <div className="flex-1 flex items-center justify-center">
                          <div className="w-4/5 border-t border-gray-700/60" />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

// Footer Section
const Footer = () => {
  return (
    <footer className="bg-gray-950 border-t border-gray-800 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-2 mb-4">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <Shield className="w-6 h-6 text-cyan-400" />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-500 bg-clip-text text-transparent">
                HIDS Dashboard
              </span>
            </div>
            <p className="text-gray-400 mb-4 max-w-md">
              Advanced URL Attack Detection System - Analyze, detect, and visualize 
              web-based threats in real-time.
            </p>
            <div className="flex space-x-4">
              <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors">
                <Github className="w-5 h-5 text-gray-400" />
              </a>
              <a href="mailto:contact@example.com" className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors">
                <Mail className="w-5 h-5 text-gray-400" />
              </a>
              <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors">
                <Linkedin className="w-5 h-5 text-gray-400" />
              </a>
            </div>
          </div>
          
          {/* Links */}
          <div>
            <h4 className="text-white font-semibold mb-4">Quick Links</h4>
            <ul className="space-y-2">
              {['Features', 'How It Works', 'Dashboard', 'Documentation'].map((link) => (
                <li key={link}>
                  <a href="#" className="text-gray-400 hover:text-cyan-400 transition-colors text-sm">
                    {link}
                  </a>
                </li>
              ))}
            </ul>
          </div>
          
          {/* Support */}
          <div>
            <h4 className="text-white font-semibold mb-4">Support</h4>
            <ul className="space-y-2">
              {['Getting Started', 'API Reference', 'FAQ', 'Contact'].map((link) => (
                <li key={link}>
                  <a href="#" className="text-gray-400 hover:text-cyan-400 transition-colors text-sm">
                    {link}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="border-t border-gray-800 pt-8 text-center">
          <p className="text-gray-500 text-sm">
            © {new Date().getFullYear()} HIDS Dashboard. Built with ❤️ for Cybersecurity.
          </p>
        </div>
      </div>
    </footer>
  );
};

// Main Landing Page Component
const LandingPage = () => {
  return (
    <div className="bg-gray-950 min-h-screen">
      <style>{`
        @keyframes gridMove {
          0% { transform: translate(0, 0); }
          100% { transform: translate(50px, 50px); }
        }
        html {
          scroll-behavior: smooth;
        }
      `}</style>
      <Navbar />
      <HeroSection />
      <FeaturesSection />
      <HowItWorksSection />
      <DashboardPreviewSection />
      <AboutSection />
      <Footer />
    </div>
  );
};

export default LandingPage;
