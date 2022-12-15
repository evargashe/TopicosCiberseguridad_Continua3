from function import *


app=Flask(__name__)
app.secret_key = "super secret key"

#Route
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/validate', methods=['POST','GET'])
def validate():
    if request.method == 'POST':
            auxurl = request.form['url']
            url = urlparse(auxurl).netloc
            si = 'url is valid'
            no = 'url isnot valid'
            if (auxurl == ''):
                flash("Empty field enter a url","danger")
                return redirect('/')

            elif(isValidURL(auxurl) == True):
                # get certificate 
                cert = certificatessl(url)
                # get issuer, not before/not after
                infoCD = visualizationCD(url)
                # get public key
                key =  publicKey(url)
                # get basic Constraints
                bC = basicConstraints(url)
                
                root = certificateRoot(url)

                verificar = verificateReporitory(url)
                flash("the url was validated successfully","success")
                return render_template(
                'validate.html', sn = si, url = auxurl ,cert = cert,  infoCD = infoCD, key = key, bC = bC,
                root1 = hex(root.__getitem__(0).serial_number), root2 = hex(root.__getitem__(1).serial_number),  
                verificar = verificar)
                """ verificar = verificar.get('bool_mozilla') """
            else:
                flash("the url was not validated correctly","error")
                return render_template('validate.html', sn = no)
        
@app.route('/TrustStoreChrome/')
def TrustStoreChrome():
    loadCertificates()
    certificate = CERT.get('chromeCertificates')
    return render_template('TrustStoreChrome.html', certificate = certificate,count=len(CERT.get('chromeCertificates')) )


@app.route('/TrustStoreMozilla/')
def TrustStoreMozilla():
    loadCertificates()
    certificate = CERT.get('mozillaCertificates')
    return render_template('TrustStoreMozilla.html',certificate = certificate,count=len(CERT.get('mozillaCertificates')))


@app.route('/TrustStoreEdge/')
def TrustStoreEdge():
    loadCertificates()
    certificate = CERT.get('edgeCertificates')
    return render_template('TrustStoreEdge.html',certificate = certificate, count=len(CERT.get('edgeCertificates')))
        

UPLOAD_FOLDER = './TrustStore'
ALLOWED_EXTENSIONS = {'txt'}


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Form():
    file= FileField()

@app.route('/uploadFile', methods=['POST','GET'])
def uploadFile():
    f = request.files['file']
    urls = []
    listRepository=dict()
    if  f.content_type == 'text/plain':
        f.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),secure_filename(f.filename)))
        with open(f.filename,'r') as file:
            for line in file:
                if isValidURL(line) == True:
                    url = urlparse(line).netloc
                    urls.append(line)
            flash('Successfully entered a plain text','filecorrect')
            return render_template('uploadFile.html', urls = urls)
    elif f == '':
        flash('Ingrese un texto plano','texto')
        return redirect('/')
    else:
        flash('Enter a plain text or the file is not a plain text .txt file' , 'notexto')
        return redirect('/')

@app.route('/uploadFile/show/', methods=['POST','GET'])
def show():
    aux = request.form.get('url')
    if isValidURL(aux) == True:
        url = urlparse(aux).netloc
        # get certificate 

        cert = certificatessl(url)
        
        # get issuer, not before/not after
        infoCD = visualizationCD(url)
        # get public key
        key =  publicKey(url)
        # get basic Constraints
        bC = basicConstraints(url)
        # root certitificate
        root = certificateRoot(url)
    return render_template("showInfo.html", root1 = hex(root.__getitem__(0).serial_number), 
    root2 = hex(root.__getitem__(1).serial_number),  aux = aux ,url = url , cert = cert,  
    infoCD = infoCD, key = key, bC = bC)


app.jinja_env.globals.update(get_relevant=verificateReporitory)



if __name__ == '__main__':
    from waitress import serve
    app.run(debug=True, host="0.0.0.0",port=5000)